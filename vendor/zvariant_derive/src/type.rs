use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::{
    self, spanned::Spanned, Attribute, Data, DataEnum, DeriveInput, Error, Fields, Generics, Ident,
};

use crate::utils::{get_signature_attribute, zvariant_path};

pub fn expand_derive(ast: DeriveInput) -> Result<TokenStream, Error> {
    let zv = zvariant_path();
    if let Some(signature) = get_signature_attribute(&ast.attrs, ast.span())? {
        // Signature already provided, easy then!
        let name = ast.ident;
        let (impl_generics, ty_generics, where_clause) = ast.generics.split_for_impl();
        return Ok(quote! {
            impl #impl_generics #zv::Type for #name #ty_generics #where_clause {
                #[inline]
                fn signature() -> #zv::Signature<'static> {
                    // FIXME: Would be nice if we had a parsed `Signature` in the macro code already so
                    // it's checked at the build time but currently that's not easily possible w/o
                    // zvariant_derive requiring zvaraint and we don't want it as it creates a cyclic
                    // dep. Maybe we can find a way to share the `Signature` type between the two
                    // crates?
                    #zv::Signature::from_static_str(#signature).unwrap()
                }
            }
        });
    }

    match ast.data {
        Data::Struct(ds) => match ds.fields {
            Fields::Named(_) | Fields::Unnamed(_) => {
                impl_struct(ast.ident, ast.generics, ds.fields, &zv)
            }
            Fields::Unit => impl_unit_struct(ast.ident, ast.generics, &zv),
        },
        Data::Enum(data) => impl_enum(ast.ident, ast.generics, ast.attrs, data, &zv),
        _ => Err(Error::new(
            ast.span(),
            "only structs and enums supported at the moment",
        )),
    }
}

fn impl_struct(
    name: Ident,
    generics: Generics,
    fields: Fields,
    zv: &TokenStream,
) -> Result<TokenStream, Error> {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let signature = signature_for_struct(fields, zv);

    Ok(quote! {
        impl #impl_generics #zv::Type for #name #ty_generics #where_clause {
            #[inline]
            fn signature() -> #zv::Signature<'static> {
                #signature
            }
        }
    })
}

fn signature_for_struct(fields: Fields, zv: &TokenStream) -> TokenStream {
    let field_types = fields.iter().map(|field| field.ty.to_token_stream());
    let new_type = match fields {
        Fields::Named(_) => false,
        Fields::Unnamed(_) if field_types.len() == 1 => true,
        Fields::Unnamed(_) => false,
        Fields::Unit => panic!("signature_for_struct must not be called for unit fields"),
    };
    if new_type {
        quote! {
            #(
                <#field_types as #zv::Type>::signature()
             )*
        }
    } else {
        quote! {
            let mut s = <::std::string::String as ::std::convert::From<_>>::from("(");
            #(
                s.push_str(<#field_types as #zv::Type>::signature().as_str());
            )*
            s.push_str(")");

            #zv::Signature::from_string_unchecked(s)
        }
    }
}

fn impl_unit_struct(
    name: Ident,
    generics: Generics,
    zv: &TokenStream,
) -> Result<TokenStream, Error> {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics #zv::Type for #name #ty_generics #where_clause {
            #[inline]
            fn signature() -> #zv::Signature<'static> {
                #zv::Signature::from_static_str_unchecked("")
            }
        }
    })
}

fn impl_enum(
    name: Ident,
    generics: Generics,
    attrs: Vec<Attribute>,
    data: DataEnum,
    zv: &TokenStream,
) -> Result<TokenStream, Error> {
    let repr: TokenStream = match attrs.iter().find(|attr| attr.path.is_ident("repr")) {
        Some(repr_attr) => repr_attr.parse_args()?,
        None => quote! { u32 },
    };

    for variant in data.variants {
        // Ensure all variants of the enum are unit type
        match variant.fields {
            Fields::Unit => (),
            _ => return Err(Error::new(variant.span(), "must be a unit variant")),
        }
    }

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics #zv::Type for #name #ty_generics #where_clause {
            #[inline]
            fn signature() -> #zv::Signature<'static> {
                <#repr as #zv::Type>::signature()
            }
        }
    })
}
