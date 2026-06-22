use proc_macro2::TokenStream;
use quote::quote;

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
                        da.interface = Some(args.interface.clone());
                        variants.push(VariantEntry {
                            variant,
                            ty: s.ident.clone(),
                            boxed,
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
        .unwrap_or_else(|| quote!(Fields));
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
            if method == <#ty as ConcreteDescriptor>::METHOD {
                return serde_json::from_value::<#ty>(value)
                    #cons
                    .map(#name::#vn)
                    .map_err(serde::de::Error::custom);
            }
        }
    });

    let method_arms = variants.iter().map(|v| {
        let (vn, ty) = (&v.variant, &v.ty);
        quote!(#name::#vn(_) => <#ty as ConcreteDescriptor>::METHOD)
    });
    let validate_arms = variants.iter().map(|v| {
        let vn = &v.variant;
        quote!(#name::#vn(_) => Ok(()))
    });

    let missing_iface = format!("{} descriptor missing interface", name);
    let missing_method = format!("{} descriptor missing method", name);

    quote! {
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

        impl MessageDescriptor for #name {
            type Fields = #ufields;
            type Parameters = #uparams;
            fn interface(&self) -> &'static str { #iface }
            fn method(&self) -> &'static str {
                match self { #(#method_arms),* }
            }
        }

        impl MessageValidator for #name {
            fn validate(&self) -> core::result::Result<(), ValidationError> {
                match self { #(#validate_arms),* }
            }
        }
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
