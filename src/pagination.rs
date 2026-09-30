//! Streams over paginated collections.
//!
//! Every `find_*` builder with pages has `pages()` and `items()`. They send one
//! request per page, starting from the first, and stop after an empty page or
//! once `total` items have been seen. A page whose number differs from the one
//! requested fails with [`Error::UnexpectedPage`].
//!
//! `bounded_pages(n)` and `bounded_items(n)` read at most `n` pages. If more
//! remain, the stream ends with [`Error::PageLimit`],
//! so a stopped traversal is never mistaken for a complete one.
//!
//! Kibana pages by offset, so concurrent changes can skip or repeat items, and
//! most collections refuse to page past 10,000 results. These checks do not
//! give a consistent snapshot.
use futures_util::{
    StreamExt, TryStreamExt,
    future::BoxFuture,
    stream::{self, BoxStream},
};
use serde_json::Value;

use crate::{
    Error, Result,
    cases::{Case, CasePage, CommentPage},
    exceptions::ExceptionPage,
    fleet::FleetPage,
    security::{DetectionRule, RulePage},
};

/// One page of a paginated collection.
pub trait Page {
    type Item;

    /// The number of items in the whole collection when the page was read.
    fn total(&self) -> u64;
    fn items(&self) -> &[Self::Item];
    fn into_items(self) -> Vec<Self::Item>;

    /// The page number Kibana reports, if the page carries one.
    fn number(&self) -> Option<u32> {
        None
    }
}

impl Page for RulePage {
    type Item = DetectionRule;

    fn total(&self) -> u64 {
        self.total
    }
    fn number(&self) -> Option<u32> {
        Some(self.page)
    }
    fn items(&self) -> &[DetectionRule] {
        &self.data
    }
    fn into_items(self) -> Vec<DetectionRule> {
        self.data
    }
}

impl Page for CasePage {
    type Item = Case;

    fn total(&self) -> u64 {
        self.total
    }
    fn number(&self) -> Option<u32> {
        Some(self.page)
    }
    fn items(&self) -> &[Case] {
        &self.cases
    }
    fn into_items(self) -> Vec<Case> {
        self.cases
    }
}

impl Page for CommentPage {
    type Item = Value;

    fn total(&self) -> u64 {
        self.total
    }
    fn number(&self) -> Option<u32> {
        Some(self.page)
    }
    fn items(&self) -> &[Value] {
        &self.comments
    }
    fn into_items(self) -> Vec<Value> {
        self.comments
    }
}

impl<T> Page for ExceptionPage<T> {
    type Item = T;

    fn total(&self) -> u64 {
        self.total
    }
    fn number(&self) -> Option<u32> {
        Some(self.page)
    }
    fn items(&self) -> &[T] {
        &self.data
    }
    fn into_items(self) -> Vec<T> {
        self.data
    }
}

impl<T> Page for FleetPage<T> {
    type Item = T;

    fn total(&self) -> u64 {
        self.total
    }
    fn number(&self) -> Option<u32> {
        Some(self.page)
    }
    fn items(&self) -> &[T] {
        &self.items
    }
    fn into_items(self) -> Vec<T> {
        self.items
    }
}

/// A builder that can request any page of its collection.
pub(crate) trait Paged<'a>: Clone + Send + 'a {
    type Page: Page + Send + 'a;

    fn with_page(self, page: u32) -> Self;
    // Boxed rather than `impl Future`: Rust 1.88 cannot prove the lifetime bounds
    // of the unboxed future inside the page stream (rust-lang/rust#100013).
    fn fetch(self) -> BoxFuture<'a, Result<Self::Page>>;
}

/// Where a traversal stands.
enum Cursor<B> {
    /// Fetch `page` next, having seen `seen` items.
    Next {
        builder: B,
        page: u32,
        seen: u64,
    },
    /// More pages remain, but the page limit was reached.
    Limited,
    Done,
}

/// Streams pages from the first; `max_pages` bounds how many are read.
pub(crate) fn pages<'a, B: Paged<'a>>(
    builder: B,
    max_pages: Option<u32>,
) -> BoxStream<'a, Result<B::Page>> {
    let start = match max_pages {
        Some(0) => Cursor::Limited,
        _ => Cursor::Next {
            builder,
            page: 1,
            seen: 0,
        },
    };
    stream::try_unfold(start, move |cursor| next_page(cursor, max_pages)).boxed()
}

async fn next_page<'a, B: Paged<'a>>(
    cursor: Cursor<B>,
    max_pages: Option<u32>,
) -> Result<Option<(B::Page, Cursor<B>)>> {
    let (builder, page, seen) = match cursor {
        Cursor::Next {
            builder,
            page,
            seen,
        } => (builder, page, seen),
        Cursor::Limited => {
            return Err(Error::PageLimit {
                max_pages: max_pages.unwrap_or_default(),
            });
        }
        Cursor::Done => return Ok(None),
    };
    let result = builder.clone().with_page(page).fetch().await?;
    if let Some(returned) = result.number().filter(|&returned| returned != page) {
        return Err(Error::UnexpectedPage {
            requested: page,
            returned,
        });
    }
    let count = result.items().len() as u64;
    let seen = seen.saturating_add(count);
    let next = match page.checked_add(1) {
        _ if count == 0 || seen >= result.total() => Cursor::Done,
        _ if max_pages.is_some_and(|max| page >= max) => Cursor::Limited,
        Some(page) => Cursor::Next {
            builder,
            page,
            seen,
        },
        None => Cursor::Limited,
    };
    Ok(Some((result, next)))
}

pub(crate) fn items<'a, B: Paged<'a>>(
    builder: B,
    max_pages: Option<u32>,
) -> BoxStream<'a, Result<<B::Page as Page>::Item>>
where
    <B::Page as Page>::Item: Send + 'a,
{
    pages(builder, max_pages)
        .map_ok(|page| stream::iter(page.into_items().into_iter().map(Ok)))
        .try_flatten()
        .boxed()
}

/// Adds `pages()` and `items()` to a builder whose `page` setter starts at one.
macro_rules! paginated {
    ($($name:ident => $page:ty),* $(,)?) => {$(
        impl<'a> $crate::pagination::Paged<'a> for $name<'a> {
            type Page = $page;

            fn with_page(self, page: u32) -> Self {
                self.page(page)
            }

            fn fetch(self) -> ::futures_util::future::BoxFuture<'a, $crate::Result<$page>> {
                ::std::boxed::Box::pin(async move { self.send().await?.json().await })
            }
        }

        impl<'a> $name<'a> {
            /// Streams every page from the first, one request per page.
            /// Any page set on this builder is ignored.
            pub fn pages(self) -> ::futures_util::stream::BoxStream<'a, $crate::Result<$page>> {
                $crate::pagination::pages(self, None)
            }

            /// Streams every item across all pages. See [`pages`](Self::pages).
            pub fn items(
                self,
            ) -> ::futures_util::stream::BoxStream<
                'a,
                $crate::Result<<$page as $crate::pagination::Page>::Item>,
            > {
                $crate::pagination::items(self, None)
            }

            /// Like [`pages`](Self::pages), reading at most `max_pages` pages.
            /// If more remain, the stream ends with [`Error::PageLimit`](crate::Error::PageLimit).
            pub fn bounded_pages(
                self,
                max_pages: u32,
            ) -> ::futures_util::stream::BoxStream<'a, $crate::Result<$page>> {
                $crate::pagination::pages(self, Some(max_pages))
            }

            /// Like [`items`](Self::items), reading at most `max_pages` pages.
            /// If more remain, the stream ends with [`Error::PageLimit`](crate::Error::PageLimit).
            pub fn bounded_items(
                self,
                max_pages: u32,
            ) -> ::futures_util::stream::BoxStream<
                'a,
                $crate::Result<<$page as $crate::pagination::Page>::Item>,
            > {
                $crate::pagination::items(self, Some(max_pages))
            }
        }
    )*};
}
pub(crate) use paginated;
