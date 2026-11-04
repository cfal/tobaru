import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { sourceRef } from './metadata.mjs';

export default defineConfig({
  site: 'https://tobaru-rs.github.io',
  base: '/',
  trailingSlash: 'always',
  integrations: [starlight({
    title: 'tobaru',
    description: 'Configuration and operation of tobaru',
    defaultLocale: 'root',
    locales: { root: { label: 'English', lang: 'en' } },
    components: { SiteTitle: './src/components/SiteTitle.astro' },
    head: [{ tag: 'meta', attrs: { name: 'tobaru-source-ref', content: sourceRef } }],
    sidebar: [
      { label: 'Start', items: ['index', 'start/installation', 'start/first-config', 'start/configuration-model', 'start/examples'] },
      { label: 'Configuration', items: ['config/server', 'config/tcp', 'config/udp', 'config/ip-groups'] },
      { label: 'TLS', items: ['tls/server', 'tls/client'] },
      { label: 'HTTP', items: ['http/routing', 'http/actions', 'http/http2'] },
      { label: 'Operations', items: ['operations/cli', 'operations/limits', 'operations/upgrading', 'operations/dependencies'] },
    ],
  })],
});
