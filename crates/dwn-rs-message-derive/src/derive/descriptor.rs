pub use proc_macro2::TokenStream;
pub use quote::quote_spanned;
use quote::{format_ident, quote};
pub use syn::{
    parse::{Parse, ParseStream, Parser, Result},
    parse2,
    spanned::Spanned,
    DeriveInput, Token,
};
use syn::{Fields, FieldsNamed, Ident, ItemStruct, Path};

// parse the attribtutes (`interface`, `method`) from DeriveInput and return them
// as their Interface and related enum Method type
pub struct DescriptorAttr {
    pub(crate) interface: Option<syn::Path>,
    pub(crate) method: Ident,
    pub(crate) fields: Path,
    pub(crate) parameters: Option<Path>,
    pub(crate) variant: Option<Ident>,
    pub(crate) boxed: bool,
    pub(crate) no_handler: bool,
}

impl Parse for DescriptorAttr {
    fn parse(input: ParseStream) -> Result<Self> {
        let (
            mut interface,
            mut method,
            mut fields,
            mut parameters,
            mut variant,
            mut boxed,
            mut no_handler,
        ) = (None, None, None, None, None, false, false);

        while !input.is_empty() {
            let key: syn::Ident = input.parse()?;
            if key == "boxed" {
                boxed = true;
            } else if key == "no_handler" {
                no_handler = true;
            } else {
                input.parse::<Token![=]>()?;
                match key.to_string().as_str() {
                    "interface" => {
                        interface = Some(input.parse()?);
                    } // ignore if present; module wins
                    "method" => {
                        method = Some(input.parse()?);
                    }
                    "fields" => {
                        fields = Some(input.parse()?);
                    }
                    "parameters" => {
                        parameters = Some(input.parse()?);
                    }
                    "variant" => {
                        variant = Some(input.parse()?);
                    }
                    _ => return Err(syn::Error::new(key.span(), "unknown attribute")),
                }
            }
            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(Self {
            interface,
            method: method.ok_or_else(|| syn::Error::new(input.span(), "missing method"))?,
            fields: fields.ok_or_else(|| syn::Error::new(input.span(), "missing fields"))?,
            parameters,
            variant,
            boxed,
            no_handler,
        })
    }
}

pub(crate) fn impl_descriptor_macro_attr(attrs: DescriptorAttr, input: TokenStream) -> TokenStream {
    let ast: DeriveInput = parse2(input.clone()).expect("failed to parse input");
    let items: ItemStruct = parse2(input).expect("descriptor mus be a struct");

    let generics = &ast.generics;
    let where_clause = &generics.where_clause;

    let mut item_ser = items.clone();

    let ident = &items.ident;
    let item_ser_ident = format_ident!("{}Internal", &items.ident);
    let interface = match attrs.interface {
        Some(interface) => interface,
        None => {
            return syn::Error::new(
                ast.span(),
                "`#[descriptor]` requires `interface = <CONST>` \
                 (inside `#[interface]` modules it is supplied by the module header)",
            )
            .to_compile_error();
        }
    };
    let method = attrs.method;
    let fields = attrs.fields;
    let parameters = attrs.parameters;

    let deserialize_message_ident = format_ident!("{}MessageInternal", ident);

    item_ser.ident = item_ser_ident.clone();

    let mut into_idents: TokenStream = quote! {};
    let mut from_idents: TokenStream = quote! {};

    if let Fields::Named(ref mut fields) = item_ser.fields {
        let idents = move |from: Ident, fields: &FieldsNamed, ast: &DeriveInput| {
            fields
                .named
                .iter()
                .map(|field| {
                    let ident = field.ident.as_ref().expect("field must have an identifier");

                    quote_spanned! { ast.span() =>
                        #ident: #from.#ident,
                    }
                })
                .collect::<TokenStream>()
        };

        into_idents = idents(format_ident!("from"), fields, &ast);
        from_idents = idents(format_ident!("internal"), fields, &ast);

        fields.named.push(
            syn::Field::parse_named
                .parse2(quote_spanned!(ast.span() =>
                    pub interface: String
                ))
                .expect("failed to parse fields"),
        );
        fields.named.push(
            syn::Field::parse_named
                .parse2(quote_spanned!(ast.span() =>
                   pub method: String
                ))
                .expect("failed to parse fields"),
        );
    }

    let intofrom = format!("{}", &item_ser_ident);

    let output = quote_spanned! { ast.span() =>
        #[derive(serde::Serialize, serde::Deserialize, Default, Debug, PartialEq, Clone)]
        #[serde(into = #intofrom, try_from = #intofrom)]
        #items

        // `skip_serializing_none` belongs on the `Internal` struct: that's the type
        // actually serialized (the public struct uses `#[serde(into)]`). Placing it here
        // omits `None` fields on the wire regardless of macro expansion order.
        #[serde_with::skip_serializing_none]
        #[derive(serde::Deserialize, serde::Serialize, Clone)]
        #item_ser

        impl From<#ident> for #item_ser_ident {
            fn from(from: #ident) -> Self {
                #item_ser_ident {
                    interface: <#ident as crate::interfaces::messages::descriptors::ConcreteDescriptor>::INTERFACE.to_string(),
                    method: <#ident as crate::interfaces::messages::descriptors::ConcreteDescriptor>::METHOD.to_string(),
                    #into_idents
                }
            }
        }

        impl core::convert::TryFrom<#item_ser_ident> for #ident {
            type Error = String;

            fn try_from(internal: #item_ser_ident) -> core::result::Result<Self, Self::Error> {
                if internal.interface != #interface || internal.method != #method {
                    return Err(format!(
                        "Expected interface '{}' and method '{}', found interface '{}' and method '{}'",
                        #interface, #method, internal.interface, internal.method
                    ));
                }
                Ok(#ident {
                    #from_idents
                })
            }
        }

        impl #generics crate::interfaces::messages::descriptors::ConcreteDescriptor for #ident #generics #where_clause
        {
            const INTERFACE: &'static str = #interface;
            const METHOD: &'static str = #method;
            const KEY: &'static str = {
                // Concatenate INTERFACE+METHOD at compile time. The byte buffer is a named const so
                // the borrow promotes to `'static`; its length is fixed from the two consts' lengths.
                const KEY_BYTES: [u8; #interface.len() + #method.len()] =
                    crate::interfaces::messages::descriptors::concat_key(#interface, #method);
                match core::str::from_utf8(&KEY_BYTES) {
                    Ok(key) => key,
                    Err(_) => panic!("message key is not valid UTF-8"),
                }
            };
        }

        impl #generics crate::interfaces::messages::descriptors::MessageDescriptor for #ident #generics #where_clause
        {
            type Fields = #fields;
            type Parameters = #parameters;

            fn interface(&self) -> &'static str {
                <Self as crate::interfaces::messages::descriptors::ConcreteDescriptor>::INTERFACE
            }

            fn method(&self) -> &'static str {
                <Self as crate::interfaces::messages::descriptors::ConcreteDescriptor>::METHOD
            }
        }

        #[derive(serde::Deserialize)]
        struct #deserialize_message_ident<D>
        where
            D: crate::interfaces::messages::descriptors::MessageDescriptor + serde::de::DeserializeOwned,
        {
            descriptor: #ident,
            #[serde(flatten)]
            fields: D::Fields,
        }

        impl<'de> serde::Deserialize<'de> for crate::Message<#ident>
        {
            fn deserialize<Des>(deserializer: Des) -> Result<Self, Des::Error>
            where
                Des: serde::Deserializer<'de>,
            {
                // `interface`/`method` validation happens in the descriptor's
                // `TryFrom<#item_ser_ident>` impl (via `#[serde(try_from)]`), so a
                // mismatched descriptor is rejected here too — no JSON buffering needed.
                let inner: #deserialize_message_ident<#ident> = serde::Deserialize::deserialize(deserializer)?;

                Ok(crate::Message {
                    descriptor: inner.descriptor,
                    fields: inner.fields,
                })
            }
         }

        impl<'de>serde::Deserialize<'de> for crate::MessageEvent<#ident> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                #[derive(serde::Deserialize)]
                struct TempEvent {
                    pub message: crate::Message<#ident>,
                    #[serde(rename = "initialWrite")]
                    pub initial_write: Option<crate::Message<crate::interfaces::messages::descriptors::records::WriteDescriptor>>,
                }
                let temp_event = TempEvent::deserialize(deserializer)?;

                Ok(Self {
                    message: temp_event.message,
                    initial_write: temp_event.initial_write,
                })
            }
        }
    };
    output
}

#[cfg(test)]
mod tests {
    use quote::quote;
    use quote::ToTokens;
    use syn::parse_quote;

    use super::*;

    #[test]
    fn test_parse_descriptor_attr() {
        const READ: &str = "READ";
        let input = quote! {
            interface = RECORDS,
            method = READ,
            fields = alloc::vec::Vec<u32>,
            parameters = alloc::vec::Vec<u32>,
        };

        let attr: DescriptorAttr = parse2(input).unwrap();

        assert_eq!(attr.method.to_token_stream().to_string(), READ);
        assert_eq!(
            attr.fields.to_token_stream().to_string(),
            "alloc :: vec :: Vec < u32 >"
        );
        assert_eq!(
            attr.parameters.unwrap().to_token_stream().to_string(),
            "alloc :: vec :: Vec < u32 >"
        );
    }

    #[test]
    fn test_impl_descriptor_macro_attr_with_fields() {
        // Define the input struct as a token stream
        let input: TokenStream = quote! {
            pub struct Example {
                pub name: String,
                pub id: u32,
            }
        };

        // Define macro implementation attributes
        let attrs = DescriptorAttr {
            interface: Some(parse_quote! { Records }),
            method: format_ident!("ExampleMethod"),
            fields: parse_quote! { FieldsNamed },
            parameters: Some(parse_quote! { FieldsNamed }),
            variant: None,
            boxed: false,
            no_handler: false,
        };

        // Apply the macro
        let output = impl_descriptor_macro_attr(attrs, input);

        // Check for key elements in the generated code
        assert!(output.to_string().contains("ExampleInternal"));
        // Trait paths are fully qualified so consumers don't need a `use`.
        assert!(output.to_string().contains("MessageDescriptor for Example"));
        assert!(output
            .to_string()
            .contains("ConcreteDescriptor for Example"));
    }
}
