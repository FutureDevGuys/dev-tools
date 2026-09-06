use dev_tools_update::artifact::{CalendarFormat, VersionRule};
use dev_tools_update::discovery::{compare_release_tags, ReleaseComparison};

#[test]
fn explicit_calendar_tags_compare_valid_periods_without_inventing_date_syntax() {
    for (format, older, newer, invalid) in [
        (
            CalendarFormat::YearMonthDayHyphen,
            "2024-02-29",
            "2024-03-01",
            "2023-02-29",
        ),
        (
            CalendarFormat::YearMonthDayDot,
            "2024.02.29",
            "2024.03.01",
            "1900.02.29",
        ),
        (
            CalendarFormat::YearMonthDayCompact,
            "20240229",
            "20240301",
            "20240431",
        ),
        (
            CalendarFormat::YearMonthHyphen,
            "2024-12",
            "2025-01",
            "2024-13",
        ),
        (
            CalendarFormat::YearMonthDot,
            "2024.12",
            "2025.01",
            "2024.00",
        ),
    ] {
        let rule = VersionRule::CalendarTag {
            prefix: "release/".into(),
            format,
        };
        let older_tag = format!("release/{older}");
        let newer_tag = format!("release/{newer}");
        assert_eq!(
            compare_release_tags(&rule, &older_tag, &newer_tag),
            Ok(ReleaseComparison::Newer)
        );
        assert_eq!(
            compare_release_tags(&rule, &newer_tag, &older_tag),
            Ok(ReleaseComparison::Older)
        );
        assert_eq!(
            compare_release_tags(&rule, &older_tag, &older_tag),
            Ok(ReleaseComparison::Equivalent)
        );
        for invalid_tag in [
            older.to_owned(),
            format!("release/{invalid}"),
            format!("release/{older}x"),
            format!("release/{}", older.replace("2024", "0000")),
            format!("release/{}", older.replace("2024", "+024")),
        ] {
            assert!(
                compare_release_tags(&rule, &invalid_tag, &newer_tag).is_err(),
                "{invalid_tag}"
            );
        }
    }
    let rule = VersionRule::CalendarTag {
        prefix: String::new(),
        format: CalendarFormat::YearMonthDayDot,
    };
    assert_eq!(
        compare_release_tags(&rule, "2000.02.29", "2400.02.29"),
        Ok(ReleaseComparison::Newer)
    );
    for invalid in [
        "2024-02-29",
        "2024.2.29",
        "2024.02.9",
        "2024.02",
        "２０２４.02.29",
        "2024.02.29.1",
    ] {
        assert!(compare_release_tags(&rule, invalid, "2024.02.29").is_err());
    }
}

#[test]
fn ordered_versions_compare_available_against_installed() {
    for (rule, installed, available, expected) in [
        (
            VersionRule::SemverTag {
                prefix: "tool/v".into(),
            },
            "tool/v1.9.0",
            "tool/v1.10.0",
            ReleaseComparison::Newer,
        ),
        (
            VersionRule::SemverTag { prefix: "v".into() },
            "v2.0.0+old",
            "v2.0.0+new",
            ReleaseComparison::Equivalent,
        ),
        (
            VersionRule::Numeric,
            "0002.0",
            "2",
            ReleaseComparison::Equivalent,
        ),
        (
            VersionRule::Numeric,
            "9999999999999999999999999999",
            "10000000000000000000000000000",
            ReleaseComparison::Newer,
        ),
        (
            VersionRule::Calendar,
            "2024-03-01",
            "2024-02-29",
            ReleaseComparison::Older,
        ),
    ] {
        assert_eq!(
            compare_release_tags(&rule, installed, available),
            Ok(expected)
        );
    }
}

#[test]
fn opaque_and_provider_order_never_invent_an_order() {
    for rule in [VersionRule::OpaqueCheckOnly, VersionRule::ProviderOrder] {
        assert_eq!(
            compare_release_tags(&rule, "z", "a"),
            Ok(ReleaseComparison::Changed)
        );
        assert_eq!(
            compare_release_tags(&rule, "a", "z"),
            Ok(ReleaseComparison::Changed)
        );
        assert_eq!(
            compare_release_tags(&rule, "a", "a"),
            Ok(ReleaseComparison::Equivalent)
        );
    }
}

#[test]
fn invalid_or_unbounded_tags_never_report_current() {
    for rule in [
        VersionRule::OpaqueCheckOnly,
        VersionRule::ProviderOrder,
        VersionRule::Numeric,
    ] {
        for invalid in ["".to_owned(), "1\n".into(), "1".repeat(513)] {
            assert!(compare_release_tags(&rule, &invalid, "1").is_err());
            assert!(compare_release_tags(&rule, "1", &invalid).is_err());
        }
    }
    assert!(compare_release_tags(&VersionRule::Calendar, "2023-02-29", "2024-02-29").is_err());
    let semver = VersionRule::SemverTag { prefix: "v".into() };
    assert!(compare_release_tags(&semver, "1.0.0", "v1.0.0").is_err());
    assert!(compare_release_tags(&semver, "v1.0.0-alpha", "v1.0.0").is_err());
}
