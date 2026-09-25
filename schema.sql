-- Jalankan di Neon SQL Editor
--- email from komang
CREATE TABLE IF NOT EXISTS tasks (
  id           BIGSERIAL PRIMARY KEY,
  title        VARCHAR(200) NOT NULL,
  description  TEXT NOT NULL DEFAULT '',
  category     VARCHAR(40)  NOT NULL DEFAULT 'Umum',
  priority     VARCHAR(10)  NOT NULL DEFAULT 'medium' CHECK (priority IN ('low','medium','high')),
  status       VARCHAR(10)  NOT NULL DEFAULT 'todo'   CHECK (status IN ('todo','done')),
  due_date     DATE NOT NULL,
  estimate_min INT CHECK (estimate_min BETWEEN 0 AND 1440),
  actual_min   INT CHECK (actual_min BETWEEN 0 AND 1440),
  completed_at TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_tasks_due      ON tasks (due_date);
CREATE INDEX IF NOT EXISTS idx_tasks_status   ON tasks (status);
CREATE INDEX IF NOT EXISTS idx_tasks_category ON tasks (category);
CREATE INDEX IF NOT EXISTS idx_tasks_done_at  ON tasks (completed_at);