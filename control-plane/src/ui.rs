//! Embedded public product/docs site and build-free web consoles. Public pages
//! are fully server-rendered for crawlability; consoles call the versioned API
//! and never receive service credentials.

use axum::body::Body;
use axum::extract::{OriginalUri, Path};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use serde_json::json;

const USER_HTML: &str = include_str!("../ui/user.html");
const ADMIN_HTML: &str = include_str!("../ui/admin.html");
const STYLES_CSS: &str = include_str!("../ui/styles.css");
const I18N_JS: &str = include_str!("../ui/i18n.js");
const COMMON_JS: &str = include_str!("../ui/common.js");
const USER_JS: &str = include_str!("../ui/user.js");
const ADMIN_JS: &str = include_str!("../ui/admin.js");
const SEMANTIC_RESOURCE_CLIENT_JS: &str = include_str!("../ui/semantic-resource-client.mjs");
const RUNTIME_PRODUCT_LOAD_JS: &str = include_str!("../ui/runtime-product-load.mjs");

const PUBLIC_CSS: &str = include_str!("../ui/public/public.css");
const LANDING_EN: &str = include_str!("../ui/public/landing-en.html");
const LANDING_ZH: &str = include_str!("../ui/public/landing-zh-CN.html");
const CATS_MARK: &str = include_str!("../ui/public/assets/cats-mark.svg");
const CATS_LOGO: &str = include_str!("../ui/public/assets/cats-logo.svg");
const CATS_OG: &str = include_str!("../ui/public/assets/cats-og.svg");
const CATS_OG_PNG: &[u8] = include_bytes!("../ui/public/assets/cats-og.png");
const WEB_MANIFEST: &str = include_str!("../ui/public/site.webmanifest");

const PUBLIC_ORIGIN: &str = "https://cats.run";
const OPS_ORIGIN: &str = "https://ops.cats.run";
const LAST_MODIFIED: &str = "2026-08-13";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Locale {
    En,
    ZhCn,
}

impl Locale {
    fn code(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::ZhCn => "zh-CN",
        }
    }

    fn og_code(self) -> &'static str {
        match self {
            Self::En => "en_US",
            Self::ZhCn => "zh_CN",
        }
    }

    fn prefix(self) -> &'static str {
        match self {
            Self::En => "",
            Self::ZhCn => "/zh-CN",
        }
    }

    fn alternate(self) -> Self {
        match self {
            Self::En => Self::ZhCn,
            Self::ZhCn => Self::En,
        }
    }

    fn content_language_header(self) -> HeaderValue {
        match self {
            Self::En => HeaderValue::from_static("en"),
            Self::ZhCn => HeaderValue::from_static("zh-CN"),
        }
    }
}

#[derive(Clone, Copy)]
struct DocPage {
    slug: &'static str,
    title_en: &'static str,
    title_zh: &'static str,
    description_en: &'static str,
    description_zh: &'static str,
    body_en: &'static str,
    body_zh: &'static str,
}

impl DocPage {
    fn title(self, locale: Locale) -> &'static str {
        match locale {
            Locale::En => self.title_en,
            Locale::ZhCn => self.title_zh,
        }
    }

    fn description(self, locale: Locale) -> &'static str {
        match locale {
            Locale::En => self.description_en,
            Locale::ZhCn => self.description_zh,
        }
    }

    fn body(self, locale: Locale) -> &'static str {
        match locale {
            Locale::En => self.body_en,
            Locale::ZhCn => self.body_zh,
        }
    }

    fn path(self, locale: Locale) -> String {
        if self.slug.is_empty() {
            format!("{}/docs/", locale.prefix())
        } else {
            format!("{}/docs/{}/", locale.prefix(), self.slug)
        }
    }
}

const DOCS: [DocPage; 10] = [
    DocPage {
        slug: "",
        title_en: "Cats documentation",
        title_zh: "Cats 使用文档",
        description_en: "Public Cats user documentation for cloud workspaces, lifecycle, storage, endpoints, CLI, HTTP and Runtime APIs, identity, and troubleshooting.",
        description_zh: "公开的 Cats 用户文档，涵盖云端工作空间、生命周期、存储、Endpoint、CLI、HTTP 与 Runtime API、身份和故障排查。",
        body_en: include_str!("../ui/public/docs/en/index.html"),
        body_zh: include_str!("../ui/public/docs/zh-CN/index.html"),
    },
    DocPage {
        slug: "getting-started",
        title_en: "Getting started",
        title_zh: "快速入门",
        description_en: "Create and inspect a durable Cat with the current console or CLI and recover an ambiguous create response.",
        description_zh: "用当前控制台或 CLI 创建并查看持久 Cat，并恢复不明确的 Create 响应。",
        body_en: include_str!("../ui/public/docs/en/getting-started.html"),
        body_zh: include_str!("../ui/public/docs/zh-CN/getting-started.html"),
    },
    DocPage {
        slug: "cats-lifecycle",
        title_en: "Cats and lifecycle",
        title_zh: "Cat 与生命周期",
        description_en: "Learn the exact Running, Suspended, Warm, and Cold semantics and the current lifecycle mutation boundary.",
        description_zh: "了解 Running、Suspended、Warm、Cold 的准确语义与当前 Lifecycle Mutation 边界。",
        body_en: include_str!("../ui/public/docs/en/cats-lifecycle.html"),
        body_zh: include_str!("../ui/public/docs/zh-CN/cats-lifecycle.html"),
    },
    DocPage {
        slug: "storage-disks",
        title_en: "Storage and disks",
        title_zh: "存储与磁盘",
        description_en: "Create immutable-capacity RootDisk and RWO PersistentDisk resources and understand fencing and FLUSH durability.",
        description_zh: "创建容量不可变的 RootDisk 与 RWO PersistentDisk，并理解 Fencing 和 FLUSH Durability。",
        body_en: include_str!("../ui/public/docs/en/storage-disks.html"),
        body_zh: include_str!("../ui/public/docs/zh-CN/storage-disks.html"),
    },
    DocPage {
        slug: "endpoints",
        title_en: "Endpoints and networking",
        title_zh: "Endpoint 与网络",
        description_en: "Understand the target Endpoint admission model and the current release boundary.",
        description_zh: "理解目标 Endpoint Admission Model 与当前 Release 边界。",
        body_en: include_str!("../ui/public/docs/en/endpoints.html"),
        body_zh: include_str!("../ui/public/docs/zh-CN/endpoints.html"),
    },
    DocPage {
        slug: "cli-reference",
        title_en: "CLI reference",
        title_zh: "CLI 参考",
        description_en: "Reference for the WorkOS, Workspace, Cat, PersistentDisk, and exact Operation commands shipped by this release.",
        description_zh: "本 Release 发布的 WorkOS、Workspace、Cat、PersistentDisk 与精确 Operation 命令参考。",
        body_en: include_str!("../ui/public/docs/en/cli-reference.html"),
        body_zh: include_str!("../ui/public/docs/zh-CN/cli-reference.html"),
    },
    DocPage {
        slug: "api-reference",
        title_en: "HTTP API reference",
        title_zh: "HTTP API 参考",
        description_en: "Current Cats V1 HTTP API routes, authentication scopes, idempotency and concurrency headers, request examples, Operations, and structured errors.",
        description_zh: "当前 Cats V1 HTTP API 路由、身份权限、幂等与并发 Header、请求示例、Operation 与结构化错误参考。",
        body_en: include_str!("../ui/public/docs/en/api-reference.html"),
        body_zh: include_str!("../ui/public/docs/zh-CN/api-reference.html"),
    },
    DocPage {
        slug: "runtime-api",
        title_en: "Guest Runtime API",
        title_zh: "Guest Runtime API",
        description_en: "Use HTTP over /run/cats/runtime.sock to create, renew, release, and inspect work leases without a Cats SDK.",
        description_zh: "无需 Cats SDK，通过 /run/cats/runtime.sock 上的 HTTP 创建、续租、释放并查看工作租约。",
        body_en: include_str!("../ui/public/docs/en/runtime-api.html"),
        body_zh: include_str!("../ui/public/docs/zh-CN/runtime-api.html"),
    },
    DocPage {
        slug: "console-workspaces",
        title_en: "Console, identity, and workspaces",
        title_zh: "控制台、身份与工作区",
        description_en: "Use the bilingual Cats consoles with WorkOS AuthKit sessions, Account and Workspace isolation, personal workspaces, and separate admin permissions.",
        description_zh: "通过 WorkOS AuthKit 会话使用双语 Cats 控制台，了解 Account 与工作区隔离、个人工作区与独立管理员权限。",
        body_en: include_str!("../ui/public/docs/en/console-workspaces.html"),
        body_zh: include_str!("../ui/public/docs/zh-CN/console-workspaces.html"),
    },
    DocPage {
        slug: "operations-troubleshooting",
        title_en: "Operations and troubleshooting",
        title_zh: "Operation 与故障排查",
        description_en: "Track exact accepted Operations, understand structured errors, respect the cutover boundary, and collect safe evidence.",
        description_zh: "跟踪精确的已接受 Operation，理解结构化错误，遵守 Cutover 边界并收集安全证据。",
        body_en: include_str!("../ui/public/docs/en/operations-troubleshooting.html"),
        body_zh: include_str!("../ui/public/docs/zh-CN/operations-troubleshooting.html"),
    },
];

const ADMIN_GUIDE: DocPage = DocPage {
    slug: "",
    title_en: "Fleet administrator guide",
    title_zh: "Fleet 管理员指南",
    description_en: "Monitor Cats fleet capacity and lifecycle, then safely cordon, drain, uncordon, recover, and remove compute nodes.",
    description_zh: "监控 Cats Fleet 容量与生命周期，并安全地 Cordon、Drain、Uncordon、恢复与移除计算节点。",
    body_en: include_str!("../ui/ops/docs/en/index.html"),
    body_zh: include_str!("../ui/ops/docs/zh-CN/index.html"),
};

fn console_asset(content_type: &'static str, body: &'static str) -> Response {
    let mut response = body.into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        ),
    );
    headers.insert(
        "x-robots-tag",
        HeaderValue::from_static("noindex, nofollow, noarchive"),
    );
    security_headers(headers, "no-referrer");
    response
}

fn public_asset(content_type: &'static str, body: &'static str) -> Response {
    let mut response = body.into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=86400, stale-while-revalidate=604800"),
    );
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'; sandbox"),
    );
    security_headers(headers, "strict-origin-when-cross-origin");
    response
}

fn public_binary(content_type: &'static str, body: &'static [u8]) -> Response {
    let mut response = Response::new(Body::from(body));
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=86400, stale-while-revalidate=604800"),
    );
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'; sandbox"),
    );
    security_headers(headers, "strict-origin-when-cross-origin");
    response
}

fn public_html(body: String, locale: Locale) -> Response {
    let mut response = body.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300, stale-while-revalidate=86400"),
    );
    headers.insert(header::CONTENT_LANGUAGE, locale.content_language_header());
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self'; img-src 'self' data:; connect-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        ),
    );
    security_headers(headers, "strict-origin-when-cross-origin");
    response
}

fn security_headers(headers: &mut HeaderMap, referrer_policy: &'static str) {
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static(referrer_policy));
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
}

fn site_header(locale: Locale, current: &str, alternate_path: &str) -> String {
    let (product, pricing, docs, lifecycle, scope, console, menu, language) = match locale {
        Locale::En => (
            "Product",
            "Pricing",
            "Docs",
            "Lifecycle",
            "Current scope",
            "Open console",
            "Menu",
            "中文",
        ),
        Locale::ZhCn => (
            "产品",
            "价格",
            "文档",
            "生命周期",
            "当前能力",
            "打开控制台",
            "菜单",
            "English",
        ),
    };
    let home = format!("{}/", locale.prefix());
    let docs_path = format!("{}/docs/", locale.prefix());
    let pricing_path = format!("{}/#pricing", locale.prefix());
    let lifecycle_path = format!("{}/docs/cats-lifecycle/", locale.prefix());
    let scope_path = format!("{}/docs/#current-scope", locale.prefix());
    format!(
        r##"<a class="skip-link" href="#main">{skip}</a>
<header class="site-header"><div class="nav-shell">
  <a class="logo-link" href="{home}" aria-label="Cats"><img src="/assets/cats-logo.svg" alt="Cats"></a>
  <nav class="site-nav" aria-label="{menu}">
    <a href="{home}"{product_current}>{product}</a>
    <a href="{pricing_path}">{pricing}</a>
    <a href="{docs_path}"{docs_current}>{docs}</a>
    <a href="{lifecycle_path}">{lifecycle}</a>
    <a href="{scope_path}">{scope}</a>
  </nav>
  <div class="nav-actions"><a class="language-link" href="{alternate_path}" hreflang="{alternate_lang}">{language}</a><a class="button-link primary" href="/user/">{console}</a></div>
  <details class="mobile-nav"><summary>{menu}</summary><div class="mobile-nav-panel"><a href="{home}">{product}</a><a href="{pricing_path}">{pricing}</a><a href="{docs_path}">{docs}</a><a href="{lifecycle_path}">{lifecycle}</a><a href="{scope_path}">{scope}</a><a href="{alternate_path}" hreflang="{alternate_lang}">{language}</a><a href="/user/">{console}</a></div></details>
</div></header>"##,
        skip = if locale == Locale::En {
            "Skip to content"
        } else {
            "跳到正文"
        },
        product_current = if current == "product" {
            " aria-current=\"page\""
        } else {
            ""
        },
        docs_current = if current == "docs" {
            " aria-current=\"page\""
        } else {
            ""
        },
        alternate_lang = locale.alternate().code(),
    )
}

fn site_footer(locale: Locale) -> String {
    let (copy, status, product, docs, console) = match locale {
        Locale::En => (
            "Durable Linux microVM workspaces that sleep, wake, and keep their disks.",
            "Current V1 scope",
            "Product",
            "Documentation",
            "User console",
        ),
        Locale::ZhCn => (
            "可休眠、可唤醒并保留持久磁盘的 Linux microVM 工作空间。",
            "当前 V1 能力",
            "产品",
            "使用文档",
            "用户控制台",
        ),
    };
    format!(
        r#"<footer class="site-footer"><div class="footer-shell"><div class="footer-brand"><img src="/assets/cats-logo.svg" alt="Cats"><p>{copy}</p></div><nav class="footer-links" aria-label="Footer"><a href="{home}">{product}</a><a href="{docs_path}">{docs}</a><a href="{scope}">{status}</a><a href="/user/">{console}</a><span>© 2026 Cats</span></nav></div></footer>"#,
        home = format_args!("{}/", locale.prefix()),
        docs_path = format_args!("{}/docs/", locale.prefix()),
        scope = format_args!("{}/docs/#current-scope", locale.prefix()),
    )
}

struct PageMeta<'a> {
    title: &'a str,
    description: &'a str,
    path: &'a str,
    alternate_path: &'a str,
    kind: &'a str,
}

fn document(
    locale: Locale,
    meta: PageMeta<'_>,
    current: &str,
    body: &str,
    structured_data: serde_json::Value,
) -> String {
    let canonical = format!("{PUBLIC_ORIGIN}{}", meta.path);
    let alternate = format!("{PUBLIC_ORIGIN}{}", meta.alternate_path);
    let json_ld = structured_data.to_string().replace("</", "<\\/");
    format!(
        r##"<!doctype html>
<html lang="{lang}"><head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <meta name="theme-color" content="#111a31">
  <title>{title}</title>
  <meta name="description" content="{description}">
  <meta name="robots" content="index, follow, max-image-preview:large, max-snippet:-1, max-video-preview:-1">
  <link rel="canonical" href="{canonical}">
  <link rel="alternate" hreflang="en" href="{en_url}">
  <link rel="alternate" hreflang="zh-CN" href="{zh_url}">
  <link rel="alternate" hreflang="x-default" href="{default_url}">
  <meta property="og:type" content="{kind}">
  <meta property="og:site_name" content="Cats">
  <meta property="og:locale" content="{og_locale}">
  <meta property="og:title" content="{title}">
  <meta property="og:description" content="{description}">
  <meta property="og:url" content="{canonical}">
  <meta property="og:image" content="{origin}/assets/cats-og.png">
  <meta property="og:image:width" content="1200"><meta property="og:image:height" content="630">
  <meta property="og:image:alt" content="Cats — durable cloud workspaces">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="{title}"><meta name="twitter:description" content="{description}">
  <meta name="twitter:image" content="{origin}/assets/cats-og.png">
  <link rel="icon" href="/assets/cats-mark.svg" type="image/svg+xml">
  <link rel="manifest" href="/site.webmanifest">
  <link rel="stylesheet" href="/assets/public.css?v=20260725-1">
  <script type="application/ld+json">{json_ld}</script>
</head><body>{header}{body}{footer}</body></html>"##,
        lang = locale.code(),
        title = meta.title,
        description = meta.description,
        kind = meta.kind,
        en_url = if locale == Locale::En {
            canonical.as_str()
        } else {
            alternate.as_str()
        },
        zh_url = if locale == Locale::ZhCn {
            canonical.as_str()
        } else {
            alternate.as_str()
        },
        default_url = if locale == Locale::En {
            canonical.as_str()
        } else {
            alternate.as_str()
        },
        og_locale = locale.og_code(),
        origin = PUBLIC_ORIGIN,
        header = site_header(locale, current, meta.alternate_path),
        footer = site_footer(locale),
    )
}

fn landing_page(locale: Locale) -> Response {
    let (title, description, body) = match locale {
        Locale::En => (
            "Cats — Durable Linux Cloud Workspaces",
            "Cats provides durable Linux microVM workspaces that sleep when idle, wake on demand, keep standard ext4 disks, and survive host replacement.",
            LANDING_EN,
        ),
        Locale::ZhCn => (
            "Cats — 持久化 Linux 云端工作空间",
            "Cats 提供可休眠、按需唤醒的持久 Linux microVM 工作空间，使用标准 ext4 磁盘并能经受 Host 替换。",
            LANDING_ZH,
        ),
    };
    let path = format!("{}/", locale.prefix());
    let alternate_path = format!("{}/", locale.alternate().prefix());
    let structured = json!({
        "@context": "https://schema.org",
        "@graph": [
            {
                "@type": "WebSite",
                "name": "Cats",
                "url": PUBLIC_ORIGIN,
                "inLanguage": locale.code(),
                "description": description
            },
            {
                "@type": "SoftwareApplication",
                "name": "Cats",
                "applicationCategory": "DeveloperApplication",
                "operatingSystem": "Linux",
                "url": format!("{PUBLIC_ORIGIN}{path}"),
                "description": description
            }
        ]
    });
    public_html(
        document(
            locale,
            PageMeta {
                title,
                description,
                path: &path,
                alternate_path: &alternate_path,
                kind: "website",
            },
            "product",
            body,
            structured,
        ),
        locale,
    )
}

fn docs_sidebar(locale: Locale, current_slug: &str) -> String {
    let label = if locale == Locale::En {
        "Documentation"
    } else {
        "使用文档"
    };
    let links = DOCS
        .iter()
        .map(|page| {
            format!(
                "<a href=\"{}\"{}>{}</a>",
                page.path(locale),
                if page.slug == current_slug {
                    " aria-current=\"page\""
                } else {
                    ""
                },
                page.title(locale)
            )
        })
        .collect::<String>();
    format!(
        "<aside class=\"docs-sidebar\"><strong>{label}</strong>{links}</aside><details class=\"docs-mobile-index\"><summary>{label}</summary><div>{links}</div></details>"
    )
}

fn page_navigation(locale: Locale, position: usize) -> String {
    let previous = position.checked_sub(1).map(|index| DOCS[index]);
    let next = DOCS.get(position + 1).copied();
    let (previous_label, next_label) = if locale == Locale::En {
        ("Previous", "Next")
    } else {
        ("上一篇", "下一篇")
    };
    let previous = previous.map_or_else(String::new, |page| {
        format!(
            "<a href=\"{}\"><small>{previous_label}</small>{}</a>",
            page.path(locale),
            page.title(locale)
        )
    });
    let next = next.map_or_else(String::new, |page| {
        format!(
            "<a href=\"{}\"><small>{next_label}</small>{}</a>",
            page.path(locale),
            page.title(locale)
        )
    });
    format!("<nav class=\"page-nav\" aria-label=\"Pagination\">{previous}{next}</nav>")
}

fn docs_page(locale: Locale, slug: &str) -> Option<Response> {
    let position = DOCS.iter().position(|page| page.slug == slug)?;
    let page = DOCS[position];
    let path = page.path(locale);
    let alternate_path = page.path(locale.alternate());
    let docs_label = if locale == Locale::En {
        "Documentation"
    } else {
        "使用文档"
    };
    let body = format!(
        r#"<main id="main"><section class="docs-hero"><div class="content-shell"><nav class="breadcrumbs" aria-label="Breadcrumb"><a href="{home}">Cats</a><span><a href="{docs_path}">{docs_label}</a></span>{current_crumb}</nav><h1>{title}</h1><p>{description}</p></div></section><div class="content-shell docs-layout">{sidebar}<article class="doc-content">{content}{page_navigation}</article></div></main>"#,
        home = format_args!("{}/", locale.prefix()),
        docs_path = DOCS[0].path(locale),
        current_crumb = if page.slug.is_empty() {
            String::new()
        } else {
            format!("<span>{}</span>", page.title(locale))
        },
        title = page.title(locale),
        description = page.description(locale),
        sidebar = docs_sidebar(locale, page.slug),
        content = page.body(locale),
        page_navigation = page_navigation(locale, position),
    );
    let breadcrumb_items = if page.slug.is_empty() {
        json!([
            { "@type": "ListItem", "position": 1, "name": "Cats", "item": format!("{PUBLIC_ORIGIN}{}/", locale.prefix()) },
            { "@type": "ListItem", "position": 2, "name": docs_label, "item": format!("{PUBLIC_ORIGIN}{path}") }
        ])
    } else {
        json!([
            { "@type": "ListItem", "position": 1, "name": "Cats", "item": format!("{PUBLIC_ORIGIN}{}/", locale.prefix()) },
            { "@type": "ListItem", "position": 2, "name": docs_label, "item": format!("{PUBLIC_ORIGIN}{}", DOCS[0].path(locale)) },
            { "@type": "ListItem", "position": 3, "name": page.title(locale), "item": format!("{PUBLIC_ORIGIN}{path}") }
        ])
    };
    let structured = json!({
        "@context": "https://schema.org",
        "@graph": [
            {
                "@type": "TechArticle",
                "headline": page.title(locale),
                "description": page.description(locale),
                "dateModified": LAST_MODIFIED,
                "inLanguage": locale.code(),
                "mainEntityOfPage": format!("{PUBLIC_ORIGIN}{path}"),
                "author": { "@type": "Organization", "name": "Cats" },
                "publisher": { "@type": "Organization", "name": "Cats", "logo": { "@type": "ImageObject", "url": format!("{PUBLIC_ORIGIN}/assets/cats-mark.svg") } }
            },
            {
                "@type": "BreadcrumbList",
                "itemListElement": breadcrumb_items
            }
        ]
    });
    Some(public_html(
        document(
            locale,
            PageMeta {
                title: &format!("{} | Cats Docs", page.title(locale)),
                description: page.description(locale),
                path: &path,
                alternate_path: &alternate_path,
                kind: "article",
            },
            "docs",
            &body,
            structured,
        ),
        locale,
    ))
}

fn is_ops_host(headers: &HeaderMap) -> bool {
    headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(':').next())
        .is_some_and(|host| host == "ops.cats.run" || host.starts_with("ops."))
}

fn ops_guide_page(locale: Locale) -> Response {
    let path = format!("{}/docs/", locale.prefix());
    let alternate_path = format!("{}/docs/", locale.alternate().prefix());
    let canonical = format!("{OPS_ORIGIN}{path}");
    let alternate = format!("{OPS_ORIGIN}{alternate_path}");
    let (guide_label, console_label, user_docs_label, language) = match locale {
        Locale::En => (
            "Fleet guide",
            "Open admin console",
            "User documentation",
            "中文",
        ),
        Locale::ZhCn => ("Fleet 指南", "打开管理员控制台", "用户文档", "English"),
    };
    let title = ADMIN_GUIDE.title(locale);
    let description = ADMIN_GUIDE.description(locale);
    let html = format!(
        r##"<!doctype html>
<html lang="{lang}"><head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <meta name="theme-color" content="#243b67">
  <title>{title} | Cats Ops</title>
  <meta name="description" content="{description}">
  <meta name="robots" content="noindex, nofollow, noarchive">
  <link rel="canonical" href="{canonical}">
  <link rel="alternate" hreflang="en" href="{en_url}">
  <link rel="alternate" hreflang="zh-CN" href="{zh_url}">
  <link rel="icon" href="/assets/cats-mark.svg" type="image/svg+xml">
  <link rel="stylesheet" href="/assets/public.css?v=20260722-3">
</head><body>
<a class="skip-link" href="#main">{skip}</a>
<header class="site-header"><div class="nav-shell">
  <a class="logo-link" href="https://cats.run/" aria-label="Cats"><img src="/assets/cats-logo.svg" alt="Cats"></a>
  <nav class="site-nav" aria-label="{guide_label}"><a href="{path}" aria-current="page">{guide_label}</a><a href="https://cats.run{user_docs_path}">{user_docs_label}</a></nav>
  <div class="nav-actions"><a class="language-link" href="{alternate_path}" hreflang="{alternate_lang}">{language}</a><a class="button-link primary" href="/">{console_label}</a></div>
  <details class="mobile-nav"><summary>{menu}</summary><div class="mobile-nav-panel"><a href="{path}" aria-current="page">{guide_label}</a><a href="https://cats.run{user_docs_path}">{user_docs_label}</a><a href="{alternate_path}" hreflang="{alternate_lang}">{language}</a><a href="/">{console_label}</a></div></details>
</div></header>
<main id="main"><section class="docs-hero"><div class="content-shell"><nav class="breadcrumbs" aria-label="Breadcrumb"><a href="/">Cats Ops</a><span>{guide_label}</span></nav><h1>{title}</h1><p>{description}</p></div></section><div class="content-shell docs-layout"><aside class="docs-sidebar"><strong>{guide_label}</strong><a href="{path}" aria-current="page">{title}</a></aside><article class="doc-content">{content}</article></div></main>
<footer class="site-footer"><div class="footer-shell"><div class="footer-brand"><img src="/assets/cats-logo.svg" alt="Cats"><p>{description}</p></div><nav class="footer-links" aria-label="Footer"><a href="/">{console_label}</a><a href="https://cats.run{user_docs_path}">{user_docs_label}</a><span>© 2026 Cats</span></nav></div></footer>
</body></html>"##,
        lang = locale.code(),
        en_url = if locale == Locale::En {
            canonical.as_str()
        } else {
            alternate.as_str()
        },
        zh_url = if locale == Locale::ZhCn {
            canonical.as_str()
        } else {
            alternate.as_str()
        },
        skip = if locale == Locale::En {
            "Skip to content"
        } else {
            "跳到正文"
        },
        alternate_lang = locale.alternate().code(),
        menu = if locale == Locale::En {
            "Menu"
        } else {
            "菜单"
        },
        user_docs_path = format_args!("{}/docs/", locale.prefix()),
        content = ADMIN_GUIDE.body(locale),
    );
    let mut response = public_html(html, locale);
    response.headers_mut().insert(
        "x-robots-tag",
        HeaderValue::from_static("noindex, nofollow, noarchive"),
    );
    response
}

pub async fn portal(headers: HeaderMap) -> Response {
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(':').next())
        .unwrap_or_default();
    match host {
        "app.cats.run" => Redirect::permanent("https://app.cats.run/user/").into_response(),
        "admin.cats.run" => Redirect::permanent("https://ops.cats.run/").into_response(),
        _ if host.starts_with("ops.") => console_asset("text/html; charset=utf-8", ADMIN_HTML),
        _ => landing_page(Locale::En),
    }
}

pub async fn zh_home() -> Response {
    landing_page(Locale::ZhCn)
}

pub async fn zh_home_redirect() -> Redirect {
    Redirect::permanent("/zh-CN/")
}

pub async fn docs_redirect() -> Redirect {
    Redirect::permanent("/docs/")
}

pub async fn docs_detail_redirect(Path(slug): Path<String>) -> Redirect {
    Redirect::permanent(&format!("/docs/{slug}/"))
}

pub async fn zh_docs_redirect() -> Redirect {
    Redirect::permanent("/zh-CN/docs/")
}

pub async fn zh_docs_detail_redirect(Path(slug): Path<String>) -> Redirect {
    Redirect::permanent(&format!("/zh-CN/docs/{slug}/"))
}

pub async fn docs_index(headers: HeaderMap) -> Response {
    if is_ops_host(&headers) {
        ops_guide_page(Locale::En)
    } else {
        docs_page(Locale::En, "").expect("docs index exists")
    }
}

pub async fn zh_docs_index(headers: HeaderMap) -> Response {
    if is_ops_host(&headers) {
        ops_guide_page(Locale::ZhCn)
    } else {
        docs_page(Locale::ZhCn, "").expect("localized docs index exists")
    }
}

pub async fn docs_detail(headers: HeaderMap, Path(slug): Path<String>) -> Response {
    if is_ops_host(&headers) {
        if slug == "admin-guide" {
            return Redirect::permanent("/docs/").into_response();
        }
        return not_found_page(Locale::En);
    }
    docs_page(Locale::En, &slug).unwrap_or_else(|| not_found_page(Locale::En))
}

pub async fn zh_docs_detail(headers: HeaderMap, Path(slug): Path<String>) -> Response {
    if is_ops_host(&headers) {
        if slug == "admin-guide" {
            return Redirect::permanent("/zh-CN/docs/").into_response();
        }
        return not_found_page(Locale::ZhCn);
    }
    docs_page(Locale::ZhCn, &slug).unwrap_or_else(|| not_found_page(Locale::ZhCn))
}

fn not_found_page(locale: Locale) -> Response {
    let (title, description, back) = match locale {
        Locale::En => (
            "Page not found | Cats",
            "The requested Cats page does not exist.",
            "Back to documentation",
        ),
        Locale::ZhCn => (
            "页面不存在 | Cats",
            "请求的 Cats 页面不存在。",
            "返回使用文档",
        ),
    };
    let body = format!(
        "<main id=\"main\" class=\"not-found content-shell\"><div><img src=\"/assets/cats-mark.svg\" alt=\"\"><h1>404</h1><p>{description}</p><a class=\"button-link primary\" href=\"{}/docs/\">{back}</a></div></main>",
        locale.prefix()
    );
    let path = format!("{}/404", locale.prefix());
    let alternate_path = format!("{}/404", locale.alternate().prefix());
    let mut response = public_html(
        document(
            locale,
            PageMeta {
                title,
                description,
                path: &path,
                alternate_path: &alternate_path,
                kind: "website",
            },
            "",
            &body,
            json!({}),
        )
        .replace(
            "index, follow, max-image-preview:large, max-snippet:-1, max-video-preview:-1",
            "noindex, nofollow",
        ),
        locale,
    );
    *response.status_mut() = StatusCode::NOT_FOUND;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub async fn not_found(OriginalUri(uri): OriginalUri) -> Response {
    if uri.path().starts_with("/v1/") || uri.path().starts_with("/auth/") {
        let mut response = (
            StatusCode::NOT_FOUND,
            axum::Json(json!({
                "code": "not_found",
                "message": "route not found"
            })),
        )
            .into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response.headers_mut().insert(
            "x-robots-tag",
            HeaderValue::from_static("noindex, nofollow, noarchive"),
        );
        return response;
    }
    let locale = if uri.path().starts_with("/zh-CN/") {
        Locale::ZhCn
    } else {
        Locale::En
    };
    not_found_page(locale)
}

pub async fn user_console() -> Response {
    console_asset("text/html; charset=utf-8", USER_HTML)
}

pub async fn admin_console() -> Response {
    console_asset("text/html; charset=utf-8", ADMIN_HTML)
}

pub(crate) fn console_asset_routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/ui/styles.css", get(styles))
        .route("/ui/i18n.js", get(i18n_script))
        .route("/ui/common.js", get(common_script))
        .route("/ui/user.js", get(user_script))
        .route("/ui/admin.js", get(admin_script))
        .route(
            "/ui/semantic-resource-client.mjs",
            get(semantic_resource_client_script),
        )
        .route(
            "/ui/runtime-product-load.mjs",
            get(runtime_product_load_script),
        )
}

pub async fn styles() -> Response {
    console_asset("text/css; charset=utf-8", STYLES_CSS)
}

pub async fn common_script() -> Response {
    console_asset("text/javascript; charset=utf-8", COMMON_JS)
}

pub async fn i18n_script() -> Response {
    console_asset("text/javascript; charset=utf-8", I18N_JS)
}

pub async fn user_script() -> Response {
    console_asset("text/javascript; charset=utf-8", USER_JS)
}

pub async fn admin_script() -> Response {
    console_asset("text/javascript; charset=utf-8", ADMIN_JS)
}

pub async fn semantic_resource_client_script() -> Response {
    console_asset(
        "text/javascript; charset=utf-8",
        SEMANTIC_RESOURCE_CLIENT_JS,
    )
}

pub async fn runtime_product_load_script() -> Response {
    console_asset("text/javascript; charset=utf-8", RUNTIME_PRODUCT_LOAD_JS)
}

pub async fn public_styles() -> Response {
    public_asset("text/css; charset=utf-8", PUBLIC_CSS)
}

pub async fn cats_mark() -> Response {
    public_asset("image/svg+xml; charset=utf-8", CATS_MARK)
}

pub async fn cats_logo() -> Response {
    public_asset("image/svg+xml; charset=utf-8", CATS_LOGO)
}

pub async fn cats_og() -> Response {
    public_asset("image/svg+xml; charset=utf-8", CATS_OG)
}

pub async fn cats_og_png() -> Response {
    public_binary("image/png", CATS_OG_PNG)
}

pub async fn web_manifest() -> Response {
    public_asset("application/manifest+json; charset=utf-8", WEB_MANIFEST)
}

pub async fn robots(headers: HeaderMap) -> Response {
    if is_ops_host(&headers) {
        public_asset("text/plain; charset=utf-8", "User-agent: *\nDisallow: /\n")
    } else {
        public_asset(
            "text/plain; charset=utf-8",
            "User-agent: *\nAllow: /\nDisallow: /user\nDisallow: /admin\nDisallow: /auth\nDisallow: /v1\nDisallow: /metrics\n\nSitemap: https://cats.run/sitemap.xml\n",
        )
    }
}

pub async fn sitemap() -> Response {
    let mut urls = Vec::with_capacity((DOCS.len() + 1) * 2);
    urls.push(("/".to_string(), "/zh-CN/".to_string()));
    for page in DOCS {
        urls.push((page.path(Locale::En), page.path(Locale::ZhCn)));
    }
    let entries = urls
        .into_iter()
        .map(|(en, zh)| {
            format!(
                "  <url><loc>{PUBLIC_ORIGIN}{en}</loc><xhtml:link rel=\"alternate\" hreflang=\"en\" href=\"{PUBLIC_ORIGIN}{en}\"/><xhtml:link rel=\"alternate\" hreflang=\"zh-CN\" href=\"{PUBLIC_ORIGIN}{zh}\"/><xhtml:link rel=\"alternate\" hreflang=\"x-default\" href=\"{PUBLIC_ORIGIN}{en}\"/><lastmod>{LAST_MODIFIED}</lastmod><changefreq>weekly</changefreq></url>\n  <url><loc>{PUBLIC_ORIGIN}{zh}</loc><xhtml:link rel=\"alternate\" hreflang=\"en\" href=\"{PUBLIC_ORIGIN}{en}\"/><xhtml:link rel=\"alternate\" hreflang=\"zh-CN\" href=\"{PUBLIC_ORIGIN}{zh}\"/><xhtml:link rel=\"alternate\" hreflang=\"x-default\" href=\"{PUBLIC_ORIGIN}{en}\"/><lastmod>{LAST_MODIFIED}</lastmod><changefreq>weekly</changefreq></url>\n"
            )
        })
        .collect::<String>();
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\" xmlns:xhtml=\"http://www.w3.org/1999/xhtml\">\n{entries}</urlset>\n"
    );
    let mut response = xml.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml; charset=utf-8"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600, stale-while-revalidate=86400"),
    );
    security_headers(response.headers_mut(), "strict-origin-when-cross-origin");
    response
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use axum::body::to_bytes;
    use axum::extract::OriginalUri;
    use axum::http::{header, StatusCode};
    use cats_api::runtime_reconciliation::{
        RUNTIME_INTERNAL_ROUTE_NOT_FOUND_BODY, RUNTIME_INTERNAL_ROUTE_NOT_FOUND_ROBOTS,
    };

    use super::{
        console_asset_routes, not_found, ADMIN_GUIDE, ADMIN_HTML, ADMIN_JS, COMMON_JS, DOCS,
        I18N_JS, LANDING_EN, LANDING_ZH, RUNTIME_PRODUCT_LOAD_JS, SEMANTIC_RESOURCE_CLIENT_JS,
        STYLES_CSS, USER_HTML, USER_JS,
    };

    #[tokio::test]
    async fn console_serves_every_user_entry_module_dependency() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind console asset fixture");
        let address = listener
            .local_addr()
            .expect("console asset fixture address");
        let server = tokio::spawn(async move {
            axum::serve(listener, console_asset_routes::<()>())
                .await
                .expect("serve console asset fixture");
        });

        for (path, expected) in [
            (
                "/ui/semantic-resource-client.mjs",
                SEMANTIC_RESOURCE_CLIENT_JS,
            ),
            ("/ui/runtime-product-load.mjs", RUNTIME_PRODUCT_LOAD_JS),
        ] {
            let response = reqwest::get(format!("http://{address}{path}"))
                .await
                .unwrap_or_else(|error| panic!("GET {path}: {error}"));
            assert_eq!(response.status(), StatusCode::OK, "GET {path}");
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).unwrap(),
                "text/javascript; charset=utf-8",
                "GET {path}",
            );
            assert_eq!(
                response.text().await.expect("read console module"),
                expected,
                "GET {path}",
            );
        }

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn runtime_unmatched_route_fallback_has_the_shared_exact_shape() {
        let response = not_found(OriginalUri(
            "/v1/internal/runtime/volume-transitions".parse().unwrap(),
        ))
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "application/json"
        );
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CACHE_CONTROL)
                .unwrap(),
            "no-store"
        );
        assert_eq!(
            response.headers().get("x-robots-tag").unwrap(),
            RUNTIME_INTERNAL_ROUTE_NOT_FOUND_ROBOTS
        );
        assert_eq!(
            to_bytes(
                response.into_body(),
                RUNTIME_INTERNAL_ROUTE_NOT_FOUND_BODY.len()
            )
            .await
            .unwrap()
            .as_ref(),
            RUNTIME_INTERNAL_ROUTE_NOT_FOUND_BODY
        );
    }

    #[test]
    fn shipped_product_docs_use_only_the_six_lifecycle_actions() {
        let api = DOCS
            .iter()
            .find(|page| page.slug == "api-reference")
            .expect("API reference is shipped");
        let cli = DOCS
            .iter()
            .find(|page| page.slug == "cli-reference")
            .expect("CLI reference is shipped");
        let lifecycle = DOCS
            .iter()
            .find(|page| page.slug == "cats-lifecycle")
            .expect("lifecycle reference is shipped");

        for body in [api.body_en, api.body_zh] {
            for required in [
                "/actions/run",
                "/actions/suspend",
                "/actions/warm",
                "/actions/cold",
                "/actions/destroy",
            ] {
                assert!(body.contains(required), "API docs lost {required}");
            }
            for retired in ["/actions/start", "/actions/stop", "/actions/delete"] {
                assert!(!body.contains(retired), "API docs regained {retired}");
            }
        }
        for body in [cli.body_en, cli.body_zh] {
            for required in [
                "cats run CAT_ID",
                "cats suspend CAT_ID",
                "cats warm CAT_ID",
                "cats cold CAT_ID",
                "cats destroy CAT_ID",
            ] {
                assert!(body.contains(required), "CLI docs lost {required}");
            }
            for retired in [
                "cats start CAT_ID",
                "cats stop CAT_ID",
                "cats delete CAT_ID",
            ] {
                assert!(!body.contains(retired), "CLI docs regained {retired}");
            }
        }
        for body in [lifecycle.body_en, lifecycle.body_zh] {
            assert!(body.contains("Create"));
            assert!(body.contains("Run"));
            assert!(body.contains("Destroy"));
        }
    }

    fn quoted_keys(source: &str, prefix: &str) -> BTreeSet<String> {
        let mut keys = BTreeSet::new();
        let mut rest = source;
        while let Some(start) = rest.find(prefix) {
            rest = &rest[start + prefix.len()..];
            if let Some(end) = rest.find('"') {
                keys.insert(rest[..end].to_string());
                rest = &rest[end + 1..];
            } else {
                break;
            }
        }
        keys
    }

    #[test]
    fn every_static_and_direct_script_translation_key_has_both_locales() {
        let mut used = BTreeSet::new();
        for source in [USER_HTML, ADMIN_HTML] {
            used.extend(quoted_keys(source, "data-i18n=\""));
            used.extend(quoted_keys(source, "data-i18n-aria-label=\""));
            used.extend(quoted_keys(source, "data-i18n-placeholder=\""));
            used.extend(quoted_keys(source, "data-i18n-title=\""));
            used.extend(quoted_keys(source, "data-i18n-content=\""));
            used.extend(quoted_keys(source, "data-i18n-href=\""));
        }
        for source in [COMMON_JS, USER_JS, ADMIN_JS] {
            used.extend(quoted_keys(source, "t(\"").into_iter().filter(|key| {
                [
                    "language.",
                    "common.",
                    "brand.",
                    "user.",
                    "admin.",
                    "status.",
                    "kind.",
                    "operation.",
                    "error.",
                ]
                .iter()
                .any(|prefix| key.starts_with(prefix))
            }));
        }

        for key in used {
            let needle = format!("\"{key}\":");
            assert_eq!(
                I18N_JS.matches(&needle).count(),
                2,
                "translation key {key:?} must exist once in English and once in Chinese"
            );
        }
    }

    #[test]
    fn locale_selection_prefers_saved_choice_then_browser_environment() {
        for contract in [
            "window.localStorage.getItem(STORAGE_KEY)",
            "navigator.languages",
            "navigator.language",
            "locale.startsWith(\"zh-\")",
            "locale.startsWith(\"en-\")",
            "window.addEventListener(\"languagechange\"",
            "document.documentElement.lang = currentLocale",
        ] {
            assert!(
                I18N_JS.contains(contract),
                "missing locale contract: {contract}"
            );
        }
    }

    #[test]
    fn user_console_refreshes_without_probing_closed_resource_projections() {
        let load_all = USER_JS
            .split("async function loadAll")
            .nth(1)
            .and_then(|source| source.split("function render()").next())
            .expect("loadAll is present");
        for contract in ["result.cats", "result.disks", "state.operations = []"] {
            assert!(
                load_all.contains(contract),
                "missing local reset {contract:?}"
            );
        }
        for contract in [
            "window.setInterval(",
            "!document.hidden",
            "loadAll({ quiet: true })",
            "state.activeWorkspaceId",
            "new AbortController()",
            "runtimeProductLoadGeneration",
            "requestPage: authenticatedRequest",
            "cancelRuntimeProductLoad()",
        ] {
            assert!(
                USER_JS.contains(contract),
                "missing polling contract: {contract}"
            );
        }
        assert!(!USER_JS.contains("apiFetch("));
        assert!(!USER_JS.contains("state.workspaceId"));
        assert!(RUNTIME_PRODUCT_LOAD_JS.contains("export async function loadAll"));
        assert!(!RUNTIME_PRODUCT_LOAD_JS.contains("?limit="));
        assert!(!RUNTIME_PRODUCT_LOAD_JS.contains("next_cursor"));
        let initialize_auth = USER_JS
            .split("async function initializeAuth()")
            .nth(1)
            .expect("initializeAuth is present");
        let show_app = initialize_auth
            .find("showApp();")
            .expect("authenticated app is shown");
        let load_products = initialize_auth
            .find("await loadAll({ quiet: true });")
            .expect("initial product load is present");
        assert!(
            show_app < load_products,
            "authentication success must reveal the app before product reads"
        );
    }

    #[test]
    fn shipped_console_exposes_only_exact_creates_and_reads_across_the_closed_authority_boundary() {
        for contract in [
            "buildSemanticCatCreateRequest",
            "createSemanticCat",
            "buildSemanticDiskCreateRequest",
            "createSemanticDisk",
        ] {
            assert!(
                USER_JS.contains(contract),
                "missing semantic create contract {contract:?}"
            );
        }
        for contract in [
            "cat_slug:",
            "disk_slug:",
            "memory_bytes:",
            "already_exists",
            "assertSemanticConsoleRequestSupported",
        ] {
            assert!(
                SEMANTIC_RESOURCE_CLIENT_JS.contains(contract),
                "missing semantic resource contract {contract:?}"
            );
        }
        for contract in [
            "name=\"vcpus\"",
            "name=\"memory_mib\"",
            "data-view=\"cats\">",
            "data-view=\"disks\">",
            "data-view=\"operations\" hidden",
        ] {
            assert!(
                USER_HTML.contains(contract),
                "missing cutover UI contract {contract:?}"
            );
        }
        assert!(!USER_HTML.contains("name=\"boot_image_digest\""));
        assert!(!SEMANTIC_RESOURCE_CLIENT_JS.contains("boot_image:"));
        let create_handler = USER_JS
            .split("document.querySelector(\"#create-cat-form\")")
            .nth(1)
            .and_then(|source| {
                source
                    .split("document.querySelector(\"#create-disk-form\")")
                    .next()
            })
            .expect("create handler is present");
        assert!(create_handler.contains("createSemanticCat({"));
        for retired in [
            "Idempotency-Key",
            "indexedDB",
            "PendingReplayToken",
            "resumePendingProductCreates",
            "operation_id",
            "?limit=",
        ] {
            assert!(
                !create_handler.contains(retired) && !SEMANTIC_RESOURCE_CLIENT_JS.contains(retired),
                "release console retained retired protocol token {retired:?}"
            );
        }
        for retired_control in ["data-cat-action", "data-disk-action", "#exec-form"] {
            assert!(
                !USER_JS.contains(retired_control),
                "release console retained retired control {retired_control:?}"
            );
        }
        for retired_create_field in [
            "values.get(\"image\")",
            "auto_suspend: true",
            "disk: null",
            "response.cat.name",
            "waitForOperation(response.operation)",
        ] {
            assert!(
                !create_handler.contains(retired_create_field),
                "production create still uses {retired_create_field:?}"
            );
        }
        assert!(ADMIN_HTML.contains("data-view=\"nodes\" hidden"));
        assert!(ADMIN_HTML.contains("id=\"view-nodes\" hidden"));
        assert!(USER_JS.contains("assertSemanticConsoleRequestSupported(path"));
        assert!(ADMIN_JS.contains("assertSemanticConsoleRequestSupported(path"));
        assert!(SEMANTIC_RESOURCE_CLIENT_JS.contains("closedSurface"));
    }

    #[test]
    fn hidden_console_controls_remain_hidden_when_components_set_display() {
        assert!(
            STYLES_CSS.contains("[hidden] { display: none !important; }"),
            "the shared stylesheet must preserve the HTML hidden contract"
        );
    }

    #[test]
    fn user_console_exposes_exact_provisional_billing_usage() {
        for contract in [
            "data-view=\"billing\"",
            "id=\"view-billing\"",
            "id=\"billing-range-form\"",
            "id=\"billing-available-credit\"",
            "id=\"billing-topup-options\"",
            "id=\"billing-meters-table\"",
            "id=\"billing-cats-table\"",
            "id=\"billing-cat-dialog\"",
            "id=\"billing-detail-chart\"",
            "id=\"billing-detail-items-table\"",
            "id=\"billing-detail-periods-table\"",
        ] {
            assert!(
                USER_HTML.contains(contract),
                "missing billing console contract: {contract}"
            );
        }
        for contract in [
            "/billing/usage?",
            "/billing/balance",
            "/billing/checkout",
            "redirectForPayment",
            "from_ms",
            "to_ms",
            "BigInt(",
            "bucket_ms",
            "report.time_buckets",
            "renderBillingDetailChart",
            "report.latest_interval_end_unix_ms",
            "report.rate_card_id",
            "state.activeView === \"billing\"",
        ] {
            assert!(
                USER_JS.contains(contract),
                "missing billing script contract: {contract}"
            );
        }
    }

    #[test]
    fn public_landing_pages_publish_pricing_and_signup_credit() {
        for body in [LANDING_EN, LANDING_ZH] {
            for contract in ["id=\"pricing\"", "$0.07", "$0.045", "$10", "Stripe"] {
                assert!(
                    body.contains(contract),
                    "public pricing page is missing {contract:?}"
                );
            }
        }
        assert!(LANDING_EN.contains("Personal Billing Account"));
        assert!(LANDING_ZH.contains("Personal Billing Account"));
        assert!(!LANDING_EN.contains("Every new billing account receives"));
        assert!(!LANDING_ZH.contains("每个新 Billing Account"));
    }

    #[test]
    fn english_and_chinese_catalogs_have_the_same_keys_without_duplicates() {
        let mut counts = std::collections::BTreeMap::<&str, usize>::new();
        for line in I18N_JS.lines() {
            let line = line.trim_start();
            let Some(rest) = line.strip_prefix('"') else {
                continue;
            };
            let Some((key, _)) = rest.split_once("\":") else {
                continue;
            };
            if key == "zh-CN" {
                continue;
            }
            *counts.entry(key).or_default() += 1;
        }
        assert!(!counts.is_empty());
        for (key, count) in counts {
            assert_eq!(count, 2, "translation key {key:?} is missing or duplicated");
        }
    }

    #[test]
    fn dynamic_status_action_kind_and_operation_keys_have_both_locales() {
        for key in [
            "status.unknown",
            "status.creating",
            "status.starting",
            "status.running",
            "status.suspending",
            "status.suspended",
            "status.warming",
            "status.warm",
            "status.stopping",
            "status.cold",
            "status.failed",
            "status.deleted",
            "status.ready",
            "status.cordoned",
            "status.draining",
            "status.lost",
            "status.fenced",
            "status.pending",
            "status.succeeded",
            "status.available",
            "status.bound",
            "status.deleting",
            "kind.root",
            "kind.persistent",
            "admin.action.cordon",
            "admin.action.drain",
            "admin.action.fence",
            "admin.action.uncordon",
            "admin.action.cancelDrain",
            "admin.action.delete",
            "operation.cat_create",
            "operation.cat_start",
            "operation.cat_stop",
            "operation.cat_suspend",
            "operation.cat_resume",
            "operation.cat_warm",
            "operation.cat_wake",
            "operation.cat_work_wake",
            "operation.cat_auto_suspend",
            "operation.cat_credit_exhausted",
            "operation.cat_delete",
        ] {
            assert_eq!(
                I18N_JS.matches(&format!("\"{key}\":")).count(),
                2,
                "dynamic translation key {key:?} must exist in both catalogs"
            );
        }
    }

    #[test]
    fn public_docs_are_complete_bilingual_and_use_unique_slugs() {
        let mut slugs = BTreeSet::new();
        let mut all_user_content = String::new();
        assert_eq!(
            DOCS.len(),
            10,
            "the public site must expose only the user documentation set"
        );
        for page in DOCS {
            assert!(slugs.insert(page.slug), "duplicate doc slug {}", page.slug);
            for body in [page.body_en, page.body_zh] {
                assert!(
                    body.contains("<h2"),
                    "{} is missing document sections",
                    page.slug
                );
                assert!(
                    !body.contains("TODO"),
                    "{} contains unfinished content",
                    page.slug
                );
            }
            assert!(!page.title_en.is_empty() && !page.title_zh.is_empty());
            assert!(!page.description_en.is_empty() && !page.description_zh.is_empty());
            for body in [page.body_en, page.body_zh] {
                assert!(!body.contains("/v1/admin/"));
                assert!(!body.contains("cats admin node"));
                all_user_content.push_str(body);
            }
        }
        for current_contract in [
            "cats login",
            "CATS_WORKSPACE",
            "size_bytes",
            "Idempotency-Key",
        ] {
            assert!(
                all_user_content.contains(current_contract),
                "public user docs are missing current contract {current_contract:?}"
            );
        }
        for retired_contract in [
            "CATS_PROJECT",
            "/v1/projects/",
            "your-project-token",
            "Authorization: Bearer &lt;project-token&gt;",
            "cats create dev --auto-suspend",
        ] {
            assert!(
                !all_user_content.contains(retired_contract),
                "public user docs contain retired contract {retired_contract:?}"
            );
        }
        for body in [ADMIN_GUIDE.body_en, ADMIN_GUIDE.body_zh] {
            assert!(body.contains("/v1/admin/nodes"));
            assert!(!body.contains("TODO"));
        }
    }
}
