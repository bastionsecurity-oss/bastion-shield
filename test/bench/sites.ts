// Bastion Shield bench — real-world sites relevant to Swiss users plus a few
// large international ones. Home pages only, as a first-time visitor (fresh
// profile, consent banners left alone).
//
// SPDX-License-Identifier: GPL-3.0-or-later

export interface BenchSite {
  name: string;
  url: string;
  region: 'ch-de' | 'ch-fr' | 'ch-it' | 'ch' | 'de' | 'fr' | 'it' | 'intl';
}

export const SITES: BenchSite[] = [
  { name: '20min.ch', url: 'https://www.20min.ch/', region: 'ch-de' },
  { name: 'blick.ch', url: 'https://www.blick.ch/', region: 'ch-de' },
  { name: 'watson.ch', url: 'https://www.watson.ch/', region: 'ch-de' },
  { name: 'nzz.ch', url: 'https://www.nzz.ch/', region: 'ch-de' },
  { name: 'tagesanzeiger.ch', url: 'https://www.tagesanzeiger.ch/', region: 'ch-de' },
  { name: 'srf.ch', url: 'https://www.srf.ch/', region: 'ch-de' },
  { name: 'letemps.ch', url: 'https://www.letemps.ch/', region: 'ch-fr' },
  { name: 'rts.ch', url: 'https://www.rts.ch/', region: 'ch-fr' },
  { name: 'rsi.ch', url: 'https://www.rsi.ch/', region: 'ch-it' },
  { name: 'ricardo.ch', url: 'https://www.ricardo.ch/', region: 'ch' },
  { name: 'tutti.ch', url: 'https://www.tutti.ch/', region: 'ch' },
  { name: 'digitec.ch', url: 'https://www.digitec.ch/', region: 'ch' },
  { name: 'galaxus.ch', url: 'https://www.galaxus.ch/', region: 'ch' },
  { name: 'local.ch', url: 'https://www.local.ch/', region: 'ch' },
  { name: 'search.ch', url: 'https://www.search.ch/', region: 'ch' },
  { name: 'cnn.com', url: 'https://edition.cnn.com/', region: 'intl' },
  { name: 'theguardian.com', url: 'https://www.theguardian.com/', region: 'intl' },
  { name: 'spiegel.de', url: 'https://www.spiegel.de/', region: 'de' },
  { name: 'bild.de', url: 'https://www.bild.de/', region: 'de' },
  { name: 'lemonde.fr', url: 'https://www.lemonde.fr/', region: 'fr' },
  { name: 'corriere.it', url: 'https://www.corriere.it/', region: 'it' },
  { name: 'youtube.com', url: 'https://www.youtube.com/', region: 'intl' },
  { name: 'reddit.com', url: 'https://www.reddit.com/', region: 'intl' },
  { name: 'stackoverflow.com', url: 'https://stackoverflow.com/questions', region: 'intl' },
  { name: 'weather.com', url: 'https://weather.com/', region: 'intl' },
];
