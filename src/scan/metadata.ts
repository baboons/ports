import type { PageMeta } from '../shared/types.ts';

/**
 * Head-tag scraping over a bounded prefix of the response body.
 *
 * Deliberately regex-based rather than a real parser: we only ever look at
 * head metadata, we cap input at 64KB upstream, and staying dependency-free
 * keeps `npx` cold start fast. Malformed markup degrades to "no title", which
 * is an acceptable outcome for a dashboard.
 */

const ENTITIES: Record<string, string> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  nbsp: ' ',
  '#39': "'",
  '#x27': "'",
  '#x2F': '/',
  '#47': '/',
};

export function decodeEntities(input: string): string {
  return input.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (match, entity: string) => {
    const known = ENTITIES[entity];
    if (known !== undefined) return known;

    if (entity.startsWith('#x') || entity.startsWith('#X')) {
      const code = Number.parseInt(entity.slice(2), 16);
      return Number.isFinite(code) ? safeFromCodePoint(code, match) : match;
    }
    if (entity.startsWith('#')) {
      const code = Number.parseInt(entity.slice(1), 10);
      return Number.isFinite(code) ? safeFromCodePoint(code, match) : match;
    }
    return match;
  });
}

function safeFromCodePoint(code: number, fallback: string): string {
  if (code < 0 || code > 0x10ffff) return fallback;
  try {
    return String.fromCodePoint(code);
  } catch {
    return fallback;
  }
}

function clean(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const text = decodeEntities(value).replace(/\s+/g, ' ').trim();
  if (text.length === 0) return undefined;
  // Long enough for a real description, short enough not to bloat the cache.
  return text.length > 300 ? `${text.slice(0, 297)}...` : text;
}

/** Pulls the value out of an attribute, handling ", ' and bare forms. */
function attr(tag: string, name: string): string | undefined {
  const re = new RegExp(`\\b${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s"'>]+))`, 'i');
  const m = re.exec(tag);
  if (!m) return undefined;
  return m[2] ?? m[3] ?? m[4];
}

/** Every <meta> and <link> tag in the input, as raw tag strings. */
function tags(html: string, name: 'meta' | 'link'): string[] {
  const re = new RegExp(`<${name}\\b[^>]*>`, 'gi');
  return html.match(re) ?? [];
}

export interface FaviconCandidate {
  href: string;
  /** Higher is better. */
  score: number;
}

/**
 * Rank the declared icons. We prefer SVG (scales cleanly in the UI), then the
 * largest declared raster size, and treat apple-touch-icon as a decent
 * fallback because plenty of dev servers only ship that one.
 */
export function rankFavicons(html: string, baseUrl: string): FaviconCandidate[] {
  const out: FaviconCandidate[] = [];

  for (const tag of tags(html, 'link')) {
    const rel = attr(tag, 'rel')?.toLowerCase();
    if (!rel) continue;
    const rels = rel.split(/\s+/);
    const isIcon =
      rels.includes('icon') ||
      rels.includes('shortcut') ||
      rels.includes('apple-touch-icon') ||
      rels.includes('apple-touch-icon-precomposed') ||
      rels.includes('mask-icon');
    if (!isIcon) continue;

    const href = attr(tag, 'href');
    if (!href || href.trim() === '') continue;

    let score = 10;
    const type = attr(tag, 'type')?.toLowerCase() ?? '';
    const sizes = attr(tag, 'sizes')?.toLowerCase() ?? '';

    if (type.includes('svg') || href.toLowerCase().endsWith('.svg')) score += 100;
    if (rels.includes('apple-touch-icon') || rels.includes('apple-touch-icon-precomposed')) {
      score += 5;
    }
    if (rels.includes('mask-icon')) score -= 5; // monochrome, poor thumbnail

    if (sizes === 'any') {
      score += 50;
    } else {
      const dim = /(\d+)\s*x\s*(\d+)/.exec(sizes);
      if (dim?.[1]) score += Math.min(Number.parseInt(dim[1], 10) / 4, 60);
    }

    const resolved = resolveUrl(href, baseUrl);
    if (resolved) out.push({ href: resolved, score });
  }

  out.sort((a, b) => b.score - a.score);
  return out;
}

export function resolveUrl(href: string, baseUrl: string): string | undefined {
  try {
    return new URL(href, baseUrl).toString();
  } catch {
    return undefined;
  }
}

/** Extract everything we care about from an HTML document prefix. */
export function extractMeta(html: string, baseUrl: string): PageMeta {
  const meta: PageMeta = {};

  const titleMatch = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html);
  if (titleMatch?.[1]) meta.title = clean(titleMatch[1]);

  for (const tag of tags(html, 'meta')) {
    const key = (attr(tag, 'name') ?? attr(tag, 'property'))?.toLowerCase();
    if (!key) continue;
    const content = attr(tag, 'content');
    if (content === undefined) continue;

    switch (key) {
      case 'description':
        meta.description ??= clean(content);
        break;
      case 'og:title':
        meta.ogTitle ??= clean(content);
        break;
      case 'og:description':
        meta.ogDescription ??= clean(content);
        break;
      case 'og:image': {
        const resolved = resolveUrl(content, baseUrl);
        if (resolved) meta.ogImage ??= resolved;
        break;
      }
      case 'theme-color':
        meta.themeColor ??= clean(content);
        break;
      default:
        break;
    }
  }

  const icons = rankFavicons(html, baseUrl);
  // No declared icon is normal; /favicon.ico is the universal fallback and the
  // fetcher will simply record a miss if it 404s.
  meta.faviconUrl = icons[0]?.href ?? resolveUrl('/favicon.ico', baseUrl);

  // A page with no <title> but an og:title should still show a name.
  if (!meta.title && meta.ogTitle) meta.title = meta.ogTitle;
  if (!meta.description && meta.ogDescription) meta.description = meta.ogDescription;

  return meta;
}

/** Identify the stack from response headers, for a small badge in the UI. */
export function detectFramework(headers: Record<string, string>): string | undefined {
  const get = (k: string) => headers[k.toLowerCase()];

  if (get('x-nextjs-cache') || get('x-nextjs-prerender') || get('x-nextjs-stale-time')) {
    return 'Next.js';
  }
  if (get('x-remix-response')) return 'Remix';
  if (get('x-sveltekit-page')) return 'SvelteKit';
  if (get('x-turbo-charged-by')) return 'Turbo';

  const powered = get('x-powered-by');
  if (powered) {
    if (/express/i.test(powered)) return 'Express';
    if (/next\.js/i.test(powered)) return 'Next.js';
    if (/nuxt/i.test(powered)) return 'Nuxt';
    if (/php/i.test(powered)) return `PHP ${powered.replace(/^php\/?/i, '')}`.trim();
    if (/asp\.net/i.test(powered)) return 'ASP.NET';
    return powered;
  }

  const server = get('server');
  if (server) {
    if (/^gunicorn/i.test(server)) return 'Gunicorn';
    if (/^uvicorn/i.test(server)) return 'Uvicorn';
    if (/^werkzeug/i.test(server)) return 'Flask';
    if (/^webrick/i.test(server)) return 'Ruby';
    if (/^puma/i.test(server)) return 'Puma';
    if (/^nginx/i.test(server)) return 'nginx';
    if (/^apache/i.test(server)) return 'Apache';
    if (/^caddy/i.test(server)) return 'Caddy';
    if (/^vite/i.test(server)) return 'Vite';
  }

  return undefined;
}
