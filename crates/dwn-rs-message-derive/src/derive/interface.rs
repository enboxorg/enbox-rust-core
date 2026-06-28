use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use crate::{derive::descriptor::DescriptorAttr, impl_descriptor_macro_attr};

// #[interface]
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

struct VariantEntry {
    variant: syn::Ident,
    ty: syn::Ident,
    boxed: bool,
    has_handler: bool,
}

pub fn expand_interface(args: InterfaceArgs, module: syn::ItemMod) -> syn::Result<TokenStream> {
    let (_brace, items) = module
        .content
        .ok_or_else(|| syn::Error::new(module.ident.span(), "expected module content"))?;

    let mut out = Vec::new();
    let mut variants = Vec::new();

    for item in items {
        match item {
            syn::Item::Struct(mut s) => {
                match s.attrs.iter().position(|a| a.path().is_ident("descriptor")) {
                    Some(pos) => {
                        let attr = s.attrs.remove(pos);
                        let mut da: DescriptorAttr = attr.parse_args()?;
                        let variant = da.variant.clone().ok_or_else(|| {
                            syn::Error::new(
                                s.ident.span(),
                                "descriptor inside #[interface] needs `variant = <Name>`",
                            )
                        })?;
                        let boxed = da.boxed;
                        let has_handler = !da.no_handler;
                        da.interface = Some(args.interface.clone());
                        variants.push(VariantEntry {
                            variant,
                            ty: s.ident.clone(),
                            boxed,
                            has_handler,
                        });
                        out.push(impl_descriptor_macro_attr(da, quote!(#s)));
                    }
                    None => out.push(quote!(#s)),
                }
            }
            other => out.push(quote!(#other)),
        }
    }

    let union = build_union(&args, &variants);
    let attrs = &module.attrs;
    let vis = &module.vis;
    let ident = &module.ident;

    Ok(quote! {
        #(#attrs)*
        #vis mod #ident {
            #(#out)*
            #union
        }
    })
}

fn build_union(args: &InterfaceArgs, variants: &[VariantEntry]) -> TokenStream {
    let name = &args.union;
    let iface = &args.interface;
    let ufields = args
        .fields
        .clone()
        .map(|p| quote!(#p))
        .unwrap_or_else(|| quote!(crate::Fields));
    let uparams = args
        .parameters
        .clone()
        .map(|p| quote!(#p))
        .unwrap_or_else(|| quote!(()));

    let variant_defs = variants.iter().map(|v| {
        let (vn, ty) = (&v.variant, &v.ty);
        if v.boxed {
            quote!(#vn(Box<#ty>))
        } else {
            quote!(#vn(#ty))
        }
    });

    let dispatch = variants.iter().map(|v| {
        let (vn, ty) = (&v.variant, &v.ty);
        let cons = if v.boxed {
            quote!(.map(Box::new))
        } else {
            quote!()
        };
        quote! {
            if method == <#ty as crate::interfaces::messages::descriptors::ConcreteDescriptor>::METHOD {
                return serde_json::from_value::<#ty>(value)
                    #cons
                    .map(#name::#vn)
                    .map_err(serde::de::Error::custom);
            }
        }
    });

    let method_arms = variants.iter().map(|v| {
        let (vn, ty) = (&v.variant, &v.ty);
        quote!(#name::#vn(_) => <#ty as crate::interfaces::messages::descriptors::ConcreteDescriptor>::METHOD)
    });
    let validate_arms = variants.iter().map(|v| {
        let vn = &v.variant;
        quote!(#name::#vn(_) => Ok(()))
    });

    let kinds = variants.iter().map(|v| {
        let (ty, has_handler) = (&v.ty, v.has_handler);
        quote!((
            #iface,
            <#ty as crate::interfaces::messages::descriptors::ConcreteDescriptor>::METHOD,
            #has_handler
        ))
    });

    // For each concrete descriptor, generate a `FromDescriptor` impl that downcasts a borrowed
    // `Descriptor` union to `&Self`. The top-level `Descriptor::#name` variant is always boxed; the
    // inner `#name::#variant` payload is dereferenced according to `boxed`.
    let from_descriptor_impls = variants.iter().map(|v| {
        let (vn, ty) = (&v.variant, &v.ty);
        let deref = if v.boxed {
            quote!(value.as_ref())
        } else {
            quote!(value)
        };
        quote! {
            impl crate::interfaces::messages::descriptors::FromDescriptor for #ty {
                fn from_descriptor(
                    descriptor: &crate::interfaces::messages::descriptors::Descriptor,
                ) -> core::result::Result<&Self, crate::interfaces::messages::descriptors::ValidationError> {
                    if let crate::interfaces::messages::descriptors::Descriptor::#name(inner) = descriptor {
                        if let #name::#vn(value) = inner.as_ref() {
                            return Ok(#deref);
                        }
                    }
                    Err(crate::interfaces::messages::descriptors::ValidationError {
                        message: format!(
                            "expected {} {} descriptor",
                            #iface,
                            <#ty as crate::interfaces::messages::descriptors::ConcreteDescriptor>::METHOD
                        ),
                    })
                }
            }
        }
    });

    // A fieldless method discriminant for this interface (e.g. `RecordsMethod`), generated from the
    // same variant entries that back the payload union. Unlike the union, it carries no descriptor
    // payload, so it is usable as a map key / embedded discriminant. `as_str`/`from_str_opt` route
    // through each descriptor's `ConcreteDescriptor::METHOD` const — the single source of truth for
    // the wire string.
    let method_enum = format_ident!("{}Method", name);
    let method_variant_defs = variants.iter().map(|v| {
        let vn = &v.variant;
        quote!(#vn)
    });
    let method_as_str_arms = variants.iter().map(|v| {
        let (vn, ty) = (&v.variant, &v.ty);
        quote!(#method_enum::#vn => <#ty as crate::interfaces::messages::descriptors::ConcreteDescriptor>::METHOD)
    });
    // if-chain rather than a `match` with const patterns: `&str` associated consts are not usable as
    // match patterns.
    let method_from_str_arms = variants.iter().map(|v| {
        let (vn, ty) = (&v.variant, &v.ty);
        quote! {
            if s == <#ty as crate::interfaces::messages::descriptors::ConcreteDescriptor>::METHOD {
                return Some(#method_enum::#vn);
            }
        }
    });

    let missing_iface = format!("{} descriptor missing interface", name);
    let missing_method = format!("{} descriptor missing method", name);

    quote! {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum #method_enum {
            #(#method_variant_defs),*
        }

        impl #method_enum {
            /// The on-the-wire method string for this variant (from `ConcreteDescriptor::METHOD`).
            pub fn as_str(&self) -> &'static str {
                match self { #(#method_as_str_arms),* }
            }

            /// Parse a wire method string into this interface's method discriminant, if recognized.
            pub fn from_str_opt(s: &str) -> Option<Self> {
                #(#method_from_str_arms)*
                None
            }
        }

        #[derive(serde::Serialize, Debug, PartialEq, Clone)]
        #[serde(untagged)]
        pub enum #name {
            #(#variant_defs),*
        }

        impl<'de> serde::Deserialize<'de> for #name {
            fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = serde_json::Value::deserialize(deserializer)?;
                let interface = value
                    .get("interface")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| serde::de::Error::custom(#missing_iface))?;
                if interface != #iface {
                    return Err(serde::de::Error::custom(format!(
                        "expected {} interface, found {}", #iface, interface
                    )));
                }
                let method = value
                    .get("method")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| serde::de::Error::custom(#missing_method))?;
                #(#dispatch)*
                Err(serde::de::Error::custom(format!(
                    "unsupported {} method {}", #iface, method
                )))
            }
        }

        impl crate::interfaces::messages::descriptors::MessageDescriptor for #name {
            type Fields = #ufields;
            type Parameters = #uparams;
            fn interface(&self) -> &'static str { #iface }
            fn method(&self) -> &'static str {
                match self { #(#method_arms),* }
            }
        }

        impl crate::interfaces::messages::descriptors::MessageValidator for #name {
            fn validate(
                &self,
            ) -> core::result::Result<(), crate::interfaces::messages::descriptors::ValidationError> {
                match self { #(#validate_arms),* }
            }
        }

        impl crate::interfaces::messages::descriptors::InterfaceUnion for #name {
            const INTERFACE: &'static str = #iface;
            const KINDS: &'static [(&'static str, &'static str, bool)] = &[
                #(#kinds),*
            ];
        }

        #(#from_descriptor_impls)*
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::quote;

    fn args(tokens: TokenStream) -> InterfaceArgs {
        syn::parse2(tokens).expect("InterfaceArgs should parse")
    }

    fn module(tokens: TokenStream) -> syn::ItemMod {
        syn::parse2(tokens).expect("ItemMod should parse")
    }

    #[test]
    fn parses_interface_args() {
        // `parameters` is a `syn::Path`, so `()` is not valid here — the union default of
        // `()` is supplied by `build_union` when the arg is omitted, not parsed.
        let a = args(quote!(
            RECORDS,
            union = Records,
            fields = Fields,
            parameters = ReadParameters
        ));
        assert_eq!(a.interface.get_ident().unwrap().to_string(), "RECORDS");
        assert_eq!(a.union.to_string(), "Records");
        assert!(a.fields.is_some());
        assert!(a.parameters.is_some());
    }

    #[test]
    fn missing_union_is_an_error() {
        assert!(syn::parse2::<InterfaceArgs>(quote!(RECORDS)).is_err());
    }

    #[test]
    fn expands_union_with_boxed_and_unboxed_variants() {
        let a = args(quote!(RECORDS, union = Records));
        let m = module(quote! {
            mod records_inner {
                #[descriptor(method = READ, variant = Read, boxed,
                             fields = Authorization, parameters = ReadParameters)]
                pub struct ReadDescriptor { pub a: u32 }

                #[descriptor(method = WRITE, variant = Write,
                             fields = Authorization, parameters = WriteParameters)]
                pub struct WriteDescriptor { pub b: u32 }
            }
        });

        let out = expand_interface(a, m)
            .expect("expansion should succeed")
            .to_string();

        // module is re-emitted
        assert!(out.contains("mod records_inner"));
        // union enum + both variants
        assert!(out.contains("enum Records"));
        assert!(out.contains("ReadDescriptor"));
        assert!(out.contains("WriteDescriptor"));
        // boxed variant wraps in Box, unboxed does not
        assert!(out.contains("Box < ReadDescriptor >"));
        assert!(out.contains("Write (WriteDescriptor)"));
        // dispatch keys off the trait const + has a fallback error
        assert!(out.contains("ConcreteDescriptor"));
        assert!(out.contains("unsupported"));
        // leaf codegen still runs (per-struct internal types)
        assert!(out.contains("ReadDescriptorInternal"));
        // fieldless method discriminant enum is generated alongside the payload union
        assert!(out.contains("enum RecordsMethod"));
        assert!(out.contains("fn as_str"));
        assert!(out.contains("fn from_str_opt"));
    }

    #[test]
    fn passes_through_non_descriptor_items() {
        let a = args(quote!(RECORDS, union = Records));
        let m = module(quote! {
            mod records_inner {
                pub struct Helper { pub x: u32 }

                #[descriptor(method = READ, variant = Read, boxed,
                             fields = Authorization, parameters = ReadParameters)]
                pub struct ReadDescriptor { pub a: u32 }
            }
        });

        let out = expand_interface(a, m)
            .expect("expansion should succeed")
            .to_string();
        assert!(out.contains("struct Helper"));
        assert!(out.contains("enum Records"));
    }

    #[test]
    fn descriptor_without_variant_is_an_error() {
        let a = args(quote!(RECORDS, union = Records));
        let m = module(quote! {
            mod records_inner {
                #[descriptor(method = READ, fields = Authorization, parameters = ReadParameters)]
                pub struct ReadDescriptor { pub a: u32 }
            }
        });

        assert!(expand_interface(a, m).is_err());
    }

    #[test]
    fn file_module_without_body_is_an_error() {
        let a = args(quote!(RECORDS, union = Records));
        let m = module(quote!(
            mod records_inner;
        ));
        assert!(expand_interface(a, m).is_err());
    }
}
