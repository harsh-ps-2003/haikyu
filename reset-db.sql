-- database: d:\codebases\hackathons\SOB\test.db


UPDATE txes
SET deleted_at = NULL;

UPDATE out_put_txes
SET spent = false;