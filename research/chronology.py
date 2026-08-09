"""Pre-registered ground-truth chronology — FROZEN at study registration.

Every date below was fixed before any study code ran. Editing this file
after the `study-preregistered` tag invalidates the study's claims.

Sources: NBER business cycle dating committee (recessions); widely
documented market events (crash windows and factor events). Windows are
[start, end] inclusive, business-day semantics applied downstream.
"""

# NBER recessions overlapping the study window (monthly turning points,
# expressed as date ranges).
NBER_RECESSIONS = [
    ("1980-01-01", "1980-07-31"),
    ("1981-07-01", "1982-11-30"),
    ("1990-07-01", "1991-03-31"),
    ("2001-03-01", "2001-11-30"),
    ("2007-12-01", "2009-06-30"),
    ("2020-02-01", "2020-04-30"),
]

# Crash/stress windows for H1 (regime) and H8 (jumps): sharp, well-dated
# market stress episodes NOT fully covered by NBER ranges.
CRASH_WINDOWS = [
    ("1987-10-14", "1987-10-30"),  # Black Monday
    ("1997-10-20", "1997-11-07"),  # Asia crisis spillover
    ("1998-08-01", "1998-10-15"),  # Russia/LTCM
    ("2000-03-10", "2000-05-31"),  # dot-com peak/rollover
    ("2010-05-05", "2010-05-12"),  # flash crash
    ("2011-07-25", "2011-08-31"),  # US downgrade
    ("2015-08-17", "2015-09-04"),  # yuan devaluation
    ("2018-02-02", "2018-02-12"),  # volmageddon
    ("2018-12-03", "2018-12-26"),  # Q4 2018 selloff
    ("2020-02-20", "2020-04-07"),  # COVID crash
    ("2022-01-03", "2022-10-14"),  # 2022 rate-shock bear (long window)
    ("2023-03-08", "2023-03-24"),  # SVB
    ("2024-08-02", "2024-08-09"),  # yen-carry unwind
]

# Event -> factor mapping for H5b (event-study spikes). Each entry:
# (date, factor_id, short label). Factors use the live taxonomy ids.
FACTOR_EVENTS = [
    ("1979-11-04", "war-conflict", "Iran hostage crisis begins"),
    ("1979-10-06", "fed-policy", "Volcker Saturday massacre"),
    ("1990-08-02", "war-conflict", "Iraq invades Kuwait"),
    ("1990-08-02", "energy-supply", "Kuwait oil supply shock"),
    ("1994-02-04", "fed-policy", "1994 surprise tightening begins"),
    ("1997-07-02", "economic-cycle", "Thai baht float / Asia crisis"),
    ("1998-08-17", "economic-cycle", "Russia default"),
    ("2001-09-11", "war-conflict", "9/11 attacks"),
    ("2001-09-11", "aviation", "9/11 aviation shutdown"),
    ("2008-09-15", "economic-cycle", "Lehman bankruptcy"),
    ("2011-08-05", "us-policy", "S&P downgrades US"),
    ("2013-05-22", "fed-policy", "Taper tantrum begins"),
    ("2015-08-11", "china-policy", "PBoC yuan devaluation"),
    ("2016-06-23", "us-policy", "Brexit referendum (policy shock proxy)"),
    ("2018-03-22", "us-china", "Section 301 tariffs announced"),
    ("2019-05-15", "semiconductors", "Huawei entity-list order"),
    ("2020-03-11", "economic-cycle", "WHO pandemic declaration"),
    ("2021-03-23", "shipping-logistics", "Ever Given blocks Suez"),
    ("2022-02-24", "war-conflict", "Russia invades Ukraine"),
    ("2022-02-24", "energy-supply", "Ukraine war energy shock"),
    ("2023-03-10", "economic-cycle", "SVB failure"),
    ("2023-10-19", "shipping-logistics", "Red Sea attacks begin"),
]

# Pre-registered era splits for H7 stability tests.
ERAS = {
    "volcker": ("1976-06-01", "1989-12-31"),
    "moderation": ("1990-01-01", "2007-12-31"),
    "zirp": ("2008-01-01", "2019-12-31"),
    "covid_inflation": ("2020-01-01", "2026-08-31"),
}

# Literature-documented causal episodes for H2 (the scan must REPRODUCE
# these known findings, not discover them).
LITERATURE_EDGES = [
    {
        "source": "DCOILWTICO_ret",
        "target": "DGS10_diff",
        "documented_era": "moderation",
        "expectation": "significant in 1986-2007, weakens post-2008",
    },
    {
        "source": "VIXCLS_diff",
        "target": "NASDAQCOM_ret",
        "documented_era": "all eras >= 1990",
        "expectation": "contemporaneous/lead relation, negative sign",
    },
]
