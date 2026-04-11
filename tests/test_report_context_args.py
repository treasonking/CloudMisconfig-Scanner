import argparse
import json

from app.main import build_report_context_from_args, load_benchmark_cases_file


def test_load_benchmark_cases_file_supports_list(tmp_path):
    bench_file = tmp_path / "bench.json"
    bench_file.write_text(
        json.dumps(
            [
                {"check_id": "AWS.S3.PublicExposure", "resource": "s3://risk", "expected": "FAIL"},
                {"check_id": "AWS.IAM.UserMFA", "resource": "iam:user/u1", "expected": "PASS"},
            ]
        ),
        encoding="utf-8",
    )

    out = load_benchmark_cases_file(str(bench_file))

    assert len(out) == 2
    assert out[0]["check_id"] == "AWS.S3.PublicExposure"


def test_build_report_context_from_args_builds_scope_and_lists(tmp_path):
    bench_file = tmp_path / "bench.json"
    bench_file.write_text(
        json.dumps({"cases": [{"check_id": "A", "resource": "r1", "expected": "FAIL"}]}),
        encoding="utf-8",
    )
    args = argparse.Namespace(
        benchmark_file=str(bench_file),
        test_target_total=20,
        normal_targets=8,
        misconfig_targets=12,
        limitation=["tag allowlist not supported"],
        improvement=["add relationship analysis"],
    )

    context = build_report_context_from_args(args)

    assert context is not None
    assert context["test_scope"]["total_cases"] == 20
    assert context["limitations"][0].startswith("tag")
    assert context["improvements"][0].startswith("add")
    assert len(context["benchmark_cases"]) == 1


def test_build_report_context_uses_default_benchmark_file(monkeypatch, tmp_path):
    default_bench = tmp_path / "benchmark-sample.json"
    default_bench.write_text(
        json.dumps({"cases": [{"check_id": "AWS.S3.PublicExposure", "resource": "s3://risk", "expected": "FAIL"}]}),
        encoding="utf-8",
    )
    monkeypatch.setattr("app.main.DEFAULT_BENCHMARK_FILE", default_bench)

    args = argparse.Namespace(
        benchmark_file=None,
        test_target_total=None,
        normal_targets=None,
        misconfig_targets=None,
        limitation=None,
        improvement=None,
    )

    context = build_report_context_from_args(args)

    assert context is not None
    assert len(context["benchmark_cases"]) == 1
