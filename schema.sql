-- Table pour les remontées de "Pour être dans le vert" (vignettes chiffrées + cartes
-- d'action prioritaires déjà calculées par l'outil), purgée chaque dimanche ~22h

CREATE TABLE IF NOT EXISTS store_stats (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  magasin TEXT NOT NULL,
  periode TEXT,             -- ex: "juillet 2026"
  date_extraction TEXT,     -- date affichée dans le rapport source
  ca_total REAL,
  ca_opt REAL,
  ca_audio REAL,
  panier_moyen REAL,
  taux_tc REAL,
  taux_sop REAL,
  taux_mdc REAL,
  protheses_vendues REAL,
  taux_essai REAL,
  objectif REAL,
  raf REAL,
  prios_json TEXT,          -- cartes d'action prioritaires : [{priorite, titre, detail}, ...]
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_store_stats_date ON store_stats(date_extraction);
CREATE INDEX IF NOT EXISTS idx_store_stats_magasin ON store_stats(magasin);
