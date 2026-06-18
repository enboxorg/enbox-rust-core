use std::ops::Bound;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use dwn_rs_core::{
    canonical_rfc3339, Alias, Cursor, Directional, Filter, FilterError, FilterKey, FilterSet,
    Filters, Ordorable, Query as CoreQuery, QueryError, RangeFilter, Value,
};
use serde::de::DeserializeOwned;

use crate::{store::sqlite_store_error, SqliteConnection};

pub struct SqliteQuery<U, T> {
    conn: SqliteConnection, // read pool handle
    tenant: String,         // scope — NOT part of Filters
    table: String,
    id_col: &'static str,
    payload_col: &'static str,
    index_col: &'static str,
    or_groups: Vec<String>,     // each = "(pred AND pred ...)"
    params: Vec<SqliteValue>,   // owned + Send, crosses spawn_blocking
    order: Vec<(String, bool)>, // (sql_expr, ascending)
    limit: Option<u64>,
    cursor: Option<Cursor>,
    always_cursor: bool,
    _marker: std::marker::PhantomData<fn() -> (U, T)>, // for CoreQuery impl
}

impl<U, T> SqliteQuery<U, T> {
    pub fn new(
        conn: SqliteConnection,
        tenant: String,
        id_col: &'static str,
        payload_col: &'static str,
        index_col: &'static str,
    ) -> Self {
        Self {
            conn,
            tenant,
            table: String::new(),
            id_col,
            payload_col,
            index_col,
            or_groups: Vec::new(),
            params: Vec::new(),
            order: Vec::new(),
            limit: None,
            cursor: None,
            always_cursor: false,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<U, T> SqliteQuery<U, T> {
    pub async fn count(&self) -> Result<u64, QueryError> {
        let (where_sql, params) = self.where_clause();
        let sql = format!("SELECT COUNT(*) FROM {}{}", self.table, where_sql);

        let count: i64 = self
            .conn
            .with_reader(move |c| {
                let mut stmt = c.prepare(&sql).map_err(sqlite_store_error)?;
                stmt.query_row(rusqlite::params_from_iter(params.iter()), |row| row.get(0))
                    .map_err(sqlite_store_error)
            })
            .await
            .map_err(|e| QueryError::DbError(e.to_string()))?;

        Ok(count as u64)
    }

    fn primary_sort(&self) -> Option<(String, bool)> {
        self.order.iter().find(|(e, _)| e != self.id_col).cloned()
    }

    fn where_clause(&self) -> (String, Vec<SqliteValue>) {
        let mut sql = String::from(" WHERE tenant = ?");
        let mut params = vec![SqliteValue::from(self.tenant.clone())];

        if !self.or_groups.is_empty() {
            sql.push_str(&format!(" AND ({})", self.or_groups.join(" OR ")));
            params.extend(self.params.iter().cloned());
        }

        if let Some((expr, _)) = self.primary_sort() {
            sql.push_str(&format!(" AND {expr} IS NOT NULL"));
        }

        (sql, params)
    }

    fn predicate(
        &self,
        key: &FilterKey,
        filter: &Filter<Value>,
    ) -> Result<(String, Vec<SqliteValue>), FilterError> {
        let col = json_col(self.index_col, key);
        let path = json_path(key);
        let indexes_col = self.index_col;

        match filter {
            Filter::Equal(v) => {
                let p = SqliteValue::from(v);
                Ok((
                format!("({col} = ? OR EXISTS (SELECT 1 FROM json_each({indexes_col}, '{path}') WHERE value = ?))"),
                vec![p.clone(), p],
            ))
            }

            Filter::OneOf(vs) => {
                let params = vs.iter().map(SqliteValue::from).collect::<Vec<_>>();
                let ph = vec!["?"; params.len()].join(", ");
                Ok((
                format!("({col} IN ({ph}) OR EXISTS (SELECT 1 FROM json_each({indexes_col}, '{path}') WHERE value IN ({ph})))"),
                // bound TWICE — once per IN list:
                params.iter().cloned().chain(params.iter().cloned()).collect(),
            ))
            }

            Filter::Range(r) => {
                let (lo, hi) = match r {
                    RangeFilter::Numeric(l, h) | RangeFilter::Criterion(l, h) => (l, h),
                };
                let mut parts = Vec::new();
                let mut params = Vec::new();
                match lo {
                    Bound::Included(v) => {
                        parts.push(format!("{col} >= ?"));
                        params.push(SqliteValue::from(v));
                    }
                    Bound::Excluded(v) => {
                        parts.push(format!("{col} > ?"));
                        params.push(SqliteValue::from(v));
                    }
                    Bound::Unbounded => {}
                }
                match hi {
                    Bound::Included(v) => {
                        parts.push(format!("{col} <= ?"));
                        params.push(SqliteValue::from(v));
                    }
                    Bound::Excluded(v) => {
                        parts.push(format!("{col} < ?"));
                        params.push(SqliteValue::from(v));
                    }
                    Bound::Unbounded => {}
                }
                if parts.is_empty() {
                    return Err(FilterError::UnparseableFilter("no range bounds".into()));
                }
                Ok((format!("({})", parts.join(" AND ")), params))
            }

            Filter::Prefix(v) => {
                // range form, NOT `LIKE '{v}%'` — `%` is meaningless in >=/< comparisons
                let lo = match v {
                    Value::String(s) => s.clone(),
                    other => {
                        return Err(FilterError::UnparseableFilter(format!(
                            "prefix filter value must be a string, got {other:?}"
                        )))
                    }
                };
                match prefix_upper_bound(&lo) {
                    Some(hi) => Ok((
                        format!("({col} >= ? AND {col} < ?)"),
                        vec![lo.into(), hi.into()],
                    )),
                    None => Ok((format!("({col} >= ?)"), vec![lo.into()])), // no bound
                }
            }
        }
    }
}

impl<U, T> CoreQuery<U, T> for SqliteQuery<U, T>
where
    U: DeserializeOwned + Sync + Send,
    T: Directional + Default + Ordorable + Sync + Copy,
{
    fn from<S>(&mut self, table: S) -> &mut Self
    where
        S: Into<String>,
    {
        self.table = table.into();
        self
    }

    fn filter(
        &mut self,
        filters: &Filters,
    ) -> Result<&mut Self, dwn_rs_core::filters::errors::FilterError> {
        let set: FilterSet<Alias> = filters.into();

        for group in set {
            let mut preds = Vec::new();

            for ((key, _alias), filter) in group {
                let (pred, params) = self.predicate(&key, &filter)?;
                preds.push(pred);
                self.params.extend(params);
            }

            if !preds.is_empty() {
                self.or_groups.push(format!("({})", preds.join(" AND ")));
            }
        }

        Ok(self)
    }

    fn page(&mut self, pagination: Option<&dwn_rs_core::Pagination>) -> &mut Self {
        if let Some(pagination) = pagination {
            if let Some(limit) = pagination.limit {
                self.limit = Some(limit);
            }

            if let Some(cursor) = &pagination.cursor {
                self.cursor = Some(cursor.clone());
            }
        }

        self
    }

    fn always_cursor(&mut self) -> &mut Self {
        self.always_cursor = true;
        self
    }

    fn sort(&mut self, sort: Option<T>) -> &mut Self {
        let sort = sort.unwrap_or_default();
        self.order = sort
            .to_order()
            .into_iter()
            .map(|(field, asc)| {
                let expr = if field == "cid" {
                    self.id_col.to_string()
                } else {
                    json_col(self.index_col, &FilterKey::Index(field.to_string()))
                };

                (expr, asc)
            })
            .collect();

        self
    }

    async fn query(
        &self,
    ) -> Result<(Vec<U>, Option<dwn_rs_core::Cursor>), dwn_rs_core::filters::errors::QueryError>
    {
        if self.limit == Some(0) {
            return Ok((Vec::new(), None));
        }

        let mut sql = format!("SELECT {}, {}", self.id_col, self.payload_col);
        let mut params = Vec::<SqliteValue>::new();
        let id_col = self.id_col;

        let primary = self.order.iter().find(|(e, _)| e != self.id_col).cloned();
        if let Some((ref expr, _)) = primary {
            sql.push_str(&format!(", {expr} AS sortval"));
        } else {
            sql.push_str(", NULL as sortval");
        }

        sql.push_str(&format!(" FROM {} WHERE tenant = ?", self.table));
        params.push(SqliteValue::from(self.tenant.clone()));

        if !self.or_groups.is_empty() {
            sql.push_str(&format!(" AND ({})", self.or_groups.join(" OR ")));
            params.extend(self.params.iter().cloned());
        }

        if let Some((ref expr, _)) = primary {
            sql.push_str(&format!(" AND {expr} IS NOT NULL"));
        }

        if let Some(cursor) = &self.cursor {
            let (s, asc) = self
                .order
                .first()
                .cloned()
                .unwrap_or((self.id_col.to_string(), true));

            let op = if asc { ">" } else { "<" };
            match &cursor.value {
                Some(v) => {
                    sql.push_str(&format!(
                        " AND (({s} {op} ?) OR ({s} = ? AND {id_col} {op} ?))",
                    ));
                    let v = SqliteValue::from(v);
                    params.push(v.clone());
                    params.push(v);
                    params.push(SqliteValue::from(cursor.cursor.to_string()));
                }
                None => {
                    sql.push_str(&format!(" AND {id_col} {op} ?"));
                    params.push(SqliteValue::from(cursor.cursor.to_string()));
                }
            }
        }

        if !self.order.is_empty() {
            let cols = self
                .order
                .iter()
                .map(|(e, asc)| format!("{} {}", e, if *asc { "ASC" } else { "DESC" }))
                .collect::<Vec<_>>()
                .join(", ");
            sql.push_str(&format!(" ORDER BY {cols}"));
        } else {
            sql.push_str(&format!(" ORDER BY {id_col} ASC"));
        }

        let fetch = self.limit.map(|l| l + 1);
        if let Some(f) = fetch {
            sql.push_str(" LIMIT ?");
            params.push(SqliteValue(rusqlite::types::Value::Integer(f as i64)));
        }

        let mut rows = self
            .conn
            .with_reader(move |c| {
                let mut stmt = c.prepare(&sql).map_err(sqlite_store_error)?;
                let out = stmt
                    .query_map(rusqlite::params_from_iter(params.iter()), |row| {
                        Ok((
                            row.get::<_, String>(0)?,                         // id_col
                            row.get::<_, String>(1)?,                         // payload_col
                            row.get::<_, Option<rusqlite::types::Value>>(2)?, // sortval (optional, may be NULL)
                        ))
                    })
                    .map_err(sqlite_store_error)?
                    .collect::<Result<Vec<_>, rusqlite::Error>>()
                    .map_err(sqlite_store_error)?;

                Ok(out)
            })
            .await
            .map_err(|e| QueryError::DbError(e.to_string()))?;

        let overflow = self.limit.map_or_else(|| false, |l| rows.len() as u64 > l);
        if let Some(l) = self.limit {
            rows.truncate(l as usize);
        }

        let cursor = if (overflow || self.always_cursor) && !rows.is_empty() {
            let (cid, _, sortval) = rows.last().unwrap();
            Some(Cursor {
                cursor: cid
                    .parse()
                    .map_err(|e| QueryError::CursorError(format!("{e}")))?,
                value: sortval.clone().map(|v| SqliteValue(v).into_value()),
            })
        } else {
            None
        };

        let items = rows
            .into_iter()
            .map(|(_, json, _)| {
                serde_json::from_str::<U>(&json).map_err(|e| QueryError::DbError(e.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok((items, cursor))
    }
}

#[derive(Clone, Debug)]
pub struct SqliteValue(pub rusqlite::types::Value);
impl From<&Value> for SqliteValue {
    fn from(v: &Value) -> Self {
        use rusqlite::types::Value as R;
        SqliteValue(match v {
            Value::Null => R::Null,
            Value::Bool(b) => R::Integer(*b as i64),
            Value::String(s) => R::Text(s.clone()),
            Value::Number(i) => R::Integer(*i),
            Value::Float(f) => R::Real(*f),
            Value::DateTime(dt) => R::Text(canonical_rfc3339(*dt)),
            Value::Map(m) => R::Text(serde_json::to_string(m).unwrap_or_default()),
            Value::Array(a) => R::Text(serde_json::to_string(a).unwrap_or_default()),
            other => R::Text(other.to_string()),
        })
    }
}

impl From<String> for SqliteValue {
    fn from(s: String) -> Self {
        SqliteValue(rusqlite::types::Value::Text(s))
    }
}

impl SqliteValue {
    pub fn into_value(self) -> Value {
        use rusqlite::types::Value as R;
        match self.0 {
            R::Null => Value::Null,
            R::Integer(i) => Value::Number(i),
            R::Real(f) => Value::Float(f),
            R::Blob(b) => Value::String(STANDARD.encode(b)),
            // Text is carried VERBATIM (no DateTime/JSON sniffing). This is
            // deliberate: cursor values must round-trip byte-for-byte so the
            // keyset comparison on re-entry matches the stored column text.
            // Re-typing a timestamp-looking string would reintroduce the
            // decode->encode drift we removed.
            R::Text(s) => Value::String(s),
        }
    }
}

// drops straight into params![] / query()
impl rusqlite::ToSql for SqliteValue {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        self.0.to_sql()
    }
}

fn json_col(col: &'static str, key: &FilterKey) -> String {
    format!(
        "json_extract({col}, '$.{}')",
        key.to_string().replace('\'', "''")
    )
}

fn json_path(key: &FilterKey) -> String {
    format!("$.{}", key.to_string().replace('\'', "''"))
}

fn prefix_upper_bound(p: &str) -> Option<String> {
    let mut chars = p.chars().collect::<Vec<_>>();
    while let Some(last) = chars.pop() {
        let mut next = (last as u32).checked_add(1)?; // e.g. 'a' -> 'b'
        if next == 0xD800 {
            next = 0xE000; // skip surrogate range
        }
        if let Some(c) = char::from_u32(next) {
            let mut s: String = chars.into_iter().collect();
            s.push(c);

            return Some(s);
        }
    }

    None
}
