/**
 * Tier 2: ports worth checking before the full sweep finishes.
 *
 * These are ordered by how likely they are to be something you actually want
 * to see, because tier 2 results paint the UI while tier 3 is still running.
 */

function range(from: number, to: number): number[] {
  const out: number[] = [];
  for (let p = from; p <= to; p++) out.push(p);
  return out;
}

export const COMMON_PORTS: number[] = [
  // The classic dev-server block. Vite, CRA, Next, Nuxt, Remix all land here.
  ...range(3000, 3010),
  ...range(4000, 4010),
  ...range(5000, 5010),
  ...range(8000, 8010),
  ...range(8080, 8090),

  // Named framework defaults.
  1313, // hugo
  1420, // tauri
  1717, // roda / opennext
  2368, // ghost
  3333, // nest / adonis
  4200, // angular
  4321, // astro
  4443, // https alt
  4567, // sinatra
  4873, // verdaccio
  5173, // vite
  5174, // vite (second instance)
  5432, // postgres - not http, but people expect to see it
  5555, // prisma studio
  6006, // storybook
  6379, // redis
  7000, // airplay / misc
  7071, // azure functions
  7273, // ports (our own default neighbourhood)
  7373, // ports default
  8888, // jupyter
  8899,
  9000, // php-fpm / minio / sonarqube
  9001,
  9090, // prometheus
  9200, // elasticsearch
  9229, // node inspector
  9323, // playwright report
  11434, // ollama

  // Well-known web ports.
  80, 81, 88, 443, 591, 8008, 8443, 8834, 9443,
];

/** Deduped and sorted, so callers can rely on a stable probe order. */
export const COMMON_PORTS_UNIQUE: number[] = [...new Set(COMMON_PORTS)];
