#![no_std]

use heapless::{String, format};
use proc_macro::TokenStream;
use proc_macro2::{Literal, TokenStream as TokenStream2};
use quote::quote;
use syn::{LitStr, parse::Parser};

#[proc_macro_attribute]
pub fn stable_api(args: TokenStream, input: TokenStream) -> TokenStream {
    let args2: TokenStream2 = args.into();
    let mut since: String<32> = String::new();

    let parser = syn::meta::parser(|meta| {
        if meta.path.is_ident("since") {
            let lit: LitStr = meta.value()?.parse()?;
            since
                .push_str(lit.value().as_str())
                .expect("Cannot push doc String");
        }
        Ok(())
    });

    let _ = parser.parse2(args2);

    let doc: String<32> = format!("Stable Since {}", since).expect("Failed to format doc string");
    let item2: TokenStream2 = input.into();

    let doc_lit = Literal::string(doc.as_str());

    quote! {
        #[doc = #doc_lit]
        #item2
    }
    .into()
}

#[proc_macro_attribute]
pub fn unstable_api(_: TokenStream, _: TokenStream) -> TokenStream {
    quote! {
        #[doc = "Unstable"]
    }
    .into()
}

use syn::{DeriveInput, Item, LitInt, parse_macro_input};

#[proc_macro_derive(simd128)]
pub fn derive_simd128(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let name = &ast.ident;

    let expanded = quote! {
        const _: [(); 16] = [(); core::mem::size_of::<#name>()];

        #[cfg(all(any(target_arch="x86_64", target_arch="x86"), target_feature="sse2"))]
        impl #name {
            #[inline]
            pub unsafe fn as_m128i(&self) -> core::arch::x86_64::__m128i {
                use core::arch::x86_64::*;
                _mm_loadu_si128(self as *const _ as *const __m128i)
            }

            #[inline]
            pub unsafe fn from_m128i(v: core::arch::x86_64::__m128i) -> Self {
                use core::arch::x86_64::*;
                let mut out = core::mem::MaybeUninit::<Self>::uninit();
                _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, v);
                out.assume_init()
            }

            #[inline]
            pub unsafe fn store_from_m128i(&mut self, v: core::arch::x86_64::__m128i) {
                use core::arch::x86_64::*;
                _mm_storeu_si128(self as *mut _ as *mut __m128i, v);
            }
        }
    };
    expanded.into()
}

#[proc_macro_derive(simd256)]
pub fn derive_simd256(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let name = &ast.ident;

    let expanded = quote! {
        const _: [(); 32] = [(); core::mem::size_of::<#name>()];

        #[cfg(all(any(target_arch="x86_64", target_arch="x86"), target_feature="avx2"))]
        impl #name {
            #[inline]
            pub unsafe fn as_m256i(&self) -> core::arch::x86_64::__m256i {
                use core::arch::x86_64::*;
                _mm256_loadu_si256(self as *const _ as *const __m256i)
            }

            #[inline]
            pub unsafe fn from_m256i(v: core::arch::x86_64::__m256i) -> Self {
                use core::arch::x86_64::*;
                let mut out = core::mem::MaybeUninit::<Self>::uninit();
                _mm256_storeu_si256(out.as_mut_ptr() as *mut __m256i, v);
                out.assume_init()
            }

            #[inline]
            pub unsafe fn store_from_m256i(&mut self, v: core::arch::x86_64::__m256i) {
                use core::arch::x86_64::*;
                _mm256_storeu_si256(self as *mut _ as *mut __m256i, v);
            }
        }
    };
    expanded.into()
}

#[proc_macro_attribute]
pub fn assert_sizes(args: TokenStream, input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(args as LitInt);
    let expected_size: usize = match lit.base10_parse() {
        Ok(v) => v,
        Err(e) => return e.to_compile_error().into(),
    };

    let item = parse_macro_input!(input as Item);

    let expanded = match &item {
        Item::Struct(s) => {
            let name = &s.ident;
            quote! {
                #item
                const _: [(); core::mem::size_of::<#name>()] = [(); #expected_size];
            }
        }
        Item::Enum(e) => {
            let name = &e.ident;
            quote! {
                #item
                const _: [(); core::mem::size_of::<#name>()] = [(); #expected_size];
            }
        }
        _ => {
            quote! {
                compile_error!("`#[assert_size]` can only be used on structs, or enums");
                #item
            }
        }
    };

    expanded.into()
}
