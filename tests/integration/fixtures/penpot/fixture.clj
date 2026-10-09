(ns penpot.fixture
  (:require [app.main :as main]
            [app.migrations :as migrations])
  (:import [java.sql DriverManager]))

;; The real migration runner wraps its batch in a transaction. Use a separate
;; JDBC connection so this mutation really commits before the migration fails.
(defn fail-migration [_]
  (with-open [connection (DriverManager/getConnection
                          (str "jdbc:" (System/getenv "PENPOT_DATABASE_URI"))
                          (System/getenv "PENPOT_DATABASE_USERNAME")
                          (System/getenv "PENPOT_DATABASE_PASSWORD"))]
    (.setAutoCommit connection true)
    (with-open [statement (.createStatement connection)]
      (.executeUpdate statement "UPDATE penpot_fixture_probe SET value='candidate' WHERE id='baseline'")))
  (spit "/opt/data/assets/fixture-marker.bin" "candidate")
  (throw (ex-info "PENPOT_FIXTURE_MIGRATION_FAILURE" {})))

(alter-var-root #'migrations/migrations conj
                {:name "9999-fixture-failure" :fn fail-migration})
(apply main/-main *command-line-args*)
