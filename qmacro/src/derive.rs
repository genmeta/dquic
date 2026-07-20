use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{ToTokens, format_ident, quote};
use syn::{
    Error, Expr, ExprRange, Ident, ItemEnum, Variant,
    parse::{Parse, ParseStream},
};

pub fn quic_parameters(item: TokenStream) -> Result<TokenStream2, Error> {
    let r#enum = syn::parse::<ItemEnum>(item)?;
    let enum_name = &r#enum.ident;

    let mut try_from_varint_match_arms = quote! {};
    let mut into_varint_match_arms = quote! {};
    // TODO: validate
    let mut validate_match_arms = quote! {};
    let mut default_value_match_arms = quote! {};
    let mut value_type_match_arms = quote! {};

    for variant in &r#enum.variants {
        let discriminant = match variant.discriminant.as_ref() {
            Some((_eq, discriminant)) => discriminant,
            None => {
                return Err(Error::new_spanned(
                    variant,
                    "Each variant must have a discriminant, e.g., `= 0`",
                ));
            }
        };

        let ident = &variant.ident;
        try_from_varint_match_arms.extend(quote! {
            // u64 => Self
            #discriminant => #enum_name::#ident,
        });
        into_varint_match_arms.extend(quote! {
            // Self => u64
            #enum_name::#ident => #discriminant,
        });

        let param_args = parse_variant_attrs(variant)?;
        let validate =
            (param_args.gen_validate(ident)).map_err(|msg| Error::new_spanned(variant, msg))?;
        validate_match_arms.extend(quote! {
            #enum_name::#ident => { #validate }
        });

        let default_value = param_args.gen_default_value();
        default_value_match_arms.extend(quote! {
            #enum_name::#ident => { #default_value }
        });

        let value_type = param_args.gen_value_type();
        value_type_match_arms.extend(quote! {
            #enum_name::#ident => #value_type,
        });
    }

    Ok(quote! {
        // TODO: try from
        impl ::core::convert::TryFrom<VarInt> for #enum_name {
            type Error = Error;

            fn try_from(value: VarInt) -> Result<Self, Self::Error> {
                Ok(match value.into_u64() {
                    #try_from_varint_match_arms
                    unknown => return Err(Error::UnknownParameterId(value))
                })
            }
        }

        impl From<#enum_name> for VarInt {
            fn from(value: #enum_name) -> Self {
                VarInt::from_u64(match value {
                    #into_varint_match_arms
                }).expect("All variants should have a valid discriminant")
            }
        }

        impl #enum_name {
            pub fn validate(&self, value: &ParameterValue) -> Result<(), Error> {
                match self {
                    #validate_match_arms
                }
                Ok(())
            }

            pub fn default_value(&self) -> Option<ParameterValue> {
                match self {
                    #default_value_match_arms
                }
            }

            pub fn value_type(&self) -> ParameterValueType {
                match self {
                    #value_type_match_arms
                }
            }
        }
    })
}

fn parse_variant_attrs(variant: &Variant) -> Result<ParamArgs, Error> {
    let param_attr = variant
        .attrs
        .iter()
        .find(|attr| attr.path().is_ident("param"))
        .ok_or_else(|| {
            Error::new_spanned(
                variant,
                "Each variant must have a `#[param(...)]` attribute",
            )
        })?;

    let mut value_type = None;
    let mut default = None;
    let mut bound = None;

    param_attr.parse_nested_meta(|meta| {
        if meta.path.is_ident("value_type") {
            if value_type.is_some() {
                return Err(meta.error("duplicate `value_type` argument"));
            }
            value_type = Some(meta.value()?.parse()?);
        } else if meta.path.is_ident("default") {
            if default.is_some() {
                return Err(meta.error("duplicate `default` argument"));
            }
            default = Some(meta.value()?.parse()?);
        } else if meta.path.is_ident("bound") {
            if bound.is_some() {
                return Err(meta.error("duplicate `bound` argument"));
            }
            let value = meta.value()?.parse::<Expr>()?;
            bound = Some(match value {
                Expr::Range(range) => range,
                value => return Err(Error::new_spanned(value, "`bound` must be a range")),
            });
        } else {
            return Err(meta.error("unsupported `param` argument"));
        }
        Ok(())
    })?;

    let value_type = value_type
        .ok_or_else(|| Error::new_spanned(param_attr, "missing `value_type` argument"))?;

    Ok(ParamArgs {
        value_type,
        default,
        bound,
    })
}

struct ParamArgs {
    value_type: ParamType,
    default: Option<Expr>,
    bound: Option<ExprRange>,
}

impl ParamArgs {
    fn gen_validate(&self, id: &Ident) -> Result<TokenStream2, &'static str> {
        let Some(bound) = &self.bound else {
            return Ok(quote! {});
        };

        let value_type = format_ident!("{}", format!("{:?}", self.value_type));
        let mut convert_value = quote! {
            let ParameterValue::#value_type(v) = value else {
                return Err(Error::InvalidValueType(
                    Self::#id,
                    value.value_type(),
                ));
            };
        };

        convert_value.extend(match self.value_type {
            ParamType::VarInt => quote! { v.into_u64() },
            ParamType::Duration => quote! { v.as_millis() as u64 },
            _ => return Err("Bound is only applicable to VarInt or Duration types"),
        });

        Ok(quote! {
            let value = { #convert_value };
            if !(#bound).contains(&value) {
                return Err(Error::OutOfBounds (
                    Self::#id,
                    value,
                    #bound,
                ));
            }
        })
    }

    fn gen_default_value(&self) -> TokenStream2 {
        match &self.default {
            Some(default) => quote! { Some((#default).into()) },
            None => quote! { None },
        }
    }

    fn gen_value_type(&self) -> TokenStream2 {
        let value_type = format_ident!("{}", format!("{:?}", self.value_type));
        quote! { ParameterValueType::#value_type }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParamType {
    VarInt,
    Boolean,
    Bytes,
    Duration,
    ResetToken,
    ConnectionId,
    PreferredAddress,
}

impl Parse for ParamType {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let expr = input.parse::<Expr>()?;
        let Expr::Path(path) = expr else {
            return Err(Error::new_spanned(
                expr,
                "`value_type` must be an identifier",
            ));
        };

        match path.to_token_stream().to_string().as_str() {
            "VarInt" => Ok(ParamType::VarInt),
            "Boolean" => Ok(ParamType::Boolean),
            "Bytes" => Ok(ParamType::Bytes),
            "Duration" => Ok(ParamType::Duration),
            "ResetToken" => Ok(ParamType::ResetToken),
            "ConnectionId" => Ok(ParamType::ConnectionId),
            "PreferredAddress" => Ok(ParamType::PreferredAddress),
            other => Err(Error::new_spanned(
                path,
                format!("unsupported `value_type` `{other}`"),
            )),
        }
    }
}
