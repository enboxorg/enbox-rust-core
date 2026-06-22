pub struct InterfaceArgs {
    pub interface: syn::Path,
    pub union: syn::Ident,
    pub fields: Option<syn::Path>,
    pub parameters: Option<syn::Path>,
}

impl syn::parse::Parse for InterfaceArgs {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let interface: syn::Path = input.parse()?;
        let mut union: Option<syn::Ident> = None;
        let mut fieldss = None;
        let mut parameters = None;

        while input.peek(syn::Token![,]) {
            input.parse::<syn::Token![,]>()?;
            if input.is_empty() {
                break;
            }

            let key: syn::Ident = input.parse()?;
            input.parse::<syn::Token![=]>()?;
            match key.to_string().as_str() {
                "union" => union = Some(input.parse()?),
                "fields" => fieldss = Some(input.parse()?),
                "parameters" => parameters = Some(input.parse()?),
                _ => return Err(syn::Error::new(key.span(), "unknown attribute")),
            }
        }

        Ok(Self {
            interface,
            union: union.ok_or_else(|| syn::Error::new(input.span(), "missing union"))?,
            fields: fieldss,
            parameters,
        })
    }
}
