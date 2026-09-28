//! Streams over paginated collections.
//!
//! Every `find_*` builder with pages has `pages()` and `items()`. They send one
//! request per page, starting from the first, and stop after an empty page or
//! once `total` items have been seen. Kibana pages by offset, so concurrent
//! changes can skip or repeat items, and most collections refuse to page past
//! 10,000 results.
use std::future::Future;

use futures_util::{Stream, TryStreamExt, stream};
use serde_json::Value;

use crate::{
    Result,
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
}

impl Page for RulePage {
    type Item = DetectionRule;

    fn total(&self) -> u64 {
        self.total
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
    fn fetch(self) -> impl Future<Output = Result<Self::Page>> + Send + 'a;
}

pub(crate) fn pages<'a, B: Paged<'a>>(
    builder: B,
) -> impl Stream<Item = Result<B::Page>> + Send + 'a {
    stream::try_unfold(Some((builder, 1, 0)), |state| async move {
        let Some((builder, page, seen)) = state else {
            return Ok(None);
        };
        let result = builder.clone().with_page(page).fetch().await?;
        let count = result.items().len() as u64;
        let seen: u64 = seen + count;
        let next = (count > 0 && seen < result.total()).then_some((builder, page + 1, seen));
        Ok(Some((result, next)))
    })
}

pub(crate) fn items<'a, B: Paged<'a>>(
    builder: B,
) -> impl Stream<Item = Result<<B::Page as Page>::Item>> + Send + 'a
where
    <B::Page as Page>::Item: Send + 'a,
{
    pages(builder)
        .map_ok(|page| stream::iter(page.into_items().into_iter().map(Ok)))
        .try_flatten()
}

/// Adds `pages()` and `items()` to a builder whose `page` setter starts at one.
macro_rules! paginated {
    ($($name:ident => $page:ty),* $(,)?) => {$(
        impl<'a> $crate::pagination::Paged<'a> for $name<'a> {
            type Page = $page;

            fn with_page(self, page: u32) -> Self {
                self.page(page)
            }

            async fn fetch(self) -> $crate::Result<$page> {
                self.send().await?.json().await
            }
        }

        impl<'a> $name<'a> {
            /// Streams every page from the first, one request per page.
            /// Any page set on this builder is ignored.
            pub fn pages(self) -> impl ::futures_util::Stream<Item = $crate::Result<$page>> + Send + 'a {
                $crate::pagination::pages(self)
            }

            /// Streams every item across all pages. See [`pages`](Self::pages).
            pub fn items(
                self,
            ) -> impl ::futures_util::Stream<
                Item = $crate::Result<<$page as $crate::pagination::Page>::Item>,
            > + Send
            + 'a {
                $crate::pagination::items(self)
            }
        }
    )*};
}
pub(crate) use paginated;
