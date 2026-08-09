-- GDELT 1.0 daily aggregates for the PRISM validation study (Track A1).
-- Run against the BigQuery public dataset (free tier covers the scan):
--
--   bq query --use_legacy_sql=false --format=csv --max_rows=10000000 \
--     "$(cat research/fetch_gdelt.sql)" > research/data/gdelt_agg.csv
--
-- Output: one row per (day, CAMEO root code, actor1 country, actor2
-- country) with event count and Goldstein/tone sums. A few MB — the
-- factor mapping happens locally in studylib/gdelt.py against the frozen
-- cameo_map.py (keeps the mapping auditable and re-runnable offline).

SELECT
  PARSE_DATE('%Y%m%d', CAST(SQLDATE AS STRING)) AS date,
  SUBSTR(CAST(EventRootCode AS STRING), 1, 2) AS root_code,
  IFNULL(Actor1CountryCode, '') AS actor1,
  IFNULL(Actor2CountryCode, '') AS actor2,
  COUNT(*) AS n_events,
  SUM(GoldsteinScale) AS sum_goldstein,
  SUM(AvgTone) AS sum_tone
FROM `gdelt-bq.full.events`
WHERE SQLDATE >= 19790101
  AND EventRootCode IS NOT NULL
  AND (
    -- kinetic conflict (war-conflict factor)
    EventRootCode IN ('18', '19', '20')
    -- coercion classes (energy-supply via producer actors, filtered locally)
    OR EventRootCode IN ('13', '14', '15', '16', '17')
    -- policy/diplomacy classes (us/china-policy, fed-policy proxy)
    OR EventRootCode IN ('01', '02', '03', '04', '05', '10', '11', '12')
    -- economic cooperation (economic-cycle proxy)
    OR EventRootCode IN ('06', '07', '08')
  )
  AND (
    Actor1CountryCode IN ('USA', 'CHN', 'RUS', 'SAU', 'IRN', 'IRQ', 'KWT',
                          'VEN', 'LBY', 'ARE', 'QAT', 'UKR', 'ISR')
    OR Actor2CountryCode IN ('USA', 'CHN', 'RUS', 'SAU', 'IRN', 'IRQ', 'KWT',
                             'VEN', 'LBY', 'ARE', 'QAT', 'UKR', 'ISR')
  )
GROUP BY date, root_code, actor1, actor2
ORDER BY date
