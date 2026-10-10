import hashlib
import uuid
from datetime import datetime, timezone, timedelta
from app.core.scope_gate import is_target_in_scope, ScopeViolation, check_recon_auto_approved
from app.core.config import Settings
from app.dedup.fingerprint import compute_fingerprint, upsert_finding
from app.models.database import Base, engine, SessionLocal
from app.models.models import (
    Engagement, ScopeAuthorization, Host, Service,
    Finding, Credential, ReasoningLog, ToolJob,
)


def setup_test_db():
    Base.metadata.create_all(bind=engine)


def teardown_test_db():
    Base.metadata.drop_all(bind=engine)


def seed_engagement(db) -> Engagement:
    eng = Engagement(
        name="Test Engagement",
        client_name="Test Corp",
        status="active",
        test_type="external",
        start_date=datetime.now(timezone.utc),
        end_date=datetime.now(timezone.utc) + timedelta(days=30),
    )
    db.add(eng)
    db.commit()
    db.refresh(eng)

    scope = ScopeAuthorization(
        engagement_id=eng.id,
        allowed_targets=["192.168.1.0/24", "10.0.0.1"],
        excluded_targets=["192.168.1.100"],
        allowed_window_start=datetime.now(timezone.utc) - timedelta(hours=1),
        allowed_window_end=datetime.now(timezone.utc) + timedelta(hours=23),
        rules_of_engagement="No DoS. No social engineering.",
        approved=True,
    )
    db.add(scope)
    db.commit()
    return eng


def test_scope_gate_blocks_unauthorized():
    setup_test_db()
    db = SessionLocal()
    try:
        eng = seed_engagement(db)

        try:
            is_target_in_scope(db, eng.id, "192.168.1.50")
        except ScopeViolation:
            assert False, "In-scope target should not be blocked"

        try:
            is_target_in_scope(db, eng.id, "192.168.1.100")
            assert False, "Excluded target should be blocked"
        except ScopeViolation:
            pass

        try:
            is_target_in_scope(db, eng.id, "172.16.0.1")
            assert False, "Out-of-scope target should be blocked"
        except ScopeViolation:
            pass

        print("PASS: scope_gate")
    finally:
        db.close()
        teardown_test_db()


def test_scope_gate_blocks_outside_window():
    setup_test_db()
    db = SessionLocal()
    try:
        eng = Engagement(
            name="Window Test",
            status="active",
            start_date=datetime.now(timezone.utc),
            end_date=datetime.now(timezone.utc) + timedelta(days=30),
        )
        db.add(eng)
        db.commit()
        db.refresh(eng)

        scope = ScopeAuthorization(
            engagement_id=eng.id,
            allowed_targets=["10.0.0.0/8"],
            excluded_targets=[],
            allowed_window_start=datetime.now(timezone.utc) + timedelta(days=1),
            allowed_window_end=datetime.now(timezone.utc) + timedelta(days=2),
            approved=True,
        )
        db.add(scope)
        db.commit()

        try:
            is_target_in_scope(db, eng.id, "10.0.0.1")
            assert False, "Should block outside time window"
        except ScopeViolation:
            pass

        print("PASS: scope_gate_time_window")
    finally:
        db.close()
        teardown_test_db()


def test_scope_gate_requires_approved():
    setup_test_db()
    db = SessionLocal()
    try:
        eng = Engagement(
            name="Unapproved Test",
            status="active",
        )
        db.add(eng)
        db.commit()
        db.refresh(eng)

        scope = ScopeAuthorization(
            engagement_id=eng.id,
            allowed_targets=["10.0.0.0/8"],
            excluded_targets=[],
            allowed_window_start=datetime.now(timezone.utc) - timedelta(hours=1),
            allowed_window_end=datetime.now(timezone.utc) + timedelta(hours=1),
            approved=False,
        )
        db.add(scope)
        db.commit()

        try:
            is_target_in_scope(db, eng.id, "10.0.0.1")
            assert False, "Should block unapproved scope"
        except ScopeViolation:
            pass

        print("PASS: scope_gate_unapproved")
    finally:
        db.close()
        teardown_test_db()


def test_fingerprint_dedup():
    setup_test_db()
    db = SessionLocal()
    try:
        eng = seed_engagement(db)

        fp = compute_fingerprint("192.168.1.50", 80, "reflected_xss", "q")
        expected = hashlib.sha256(b"192.168.1.50|80|reflected_xss|q").hexdigest()
        assert fp == expected, f"Fingerprint mismatch: {fp} != {expected}"

        f1 = upsert_finding(
            db=db,
            engagement_id=eng.id,
            host_id=None,
            service_id=None,
            source_tool="zap",
            vuln_type="reflected_xss",
            severity="high",
            description="XSS in search parameter",
            parameter="q",
            fingerprint=fp,
        )

        f2 = upsert_finding(
            db=db,
            engagement_id=eng.id,
            host_id=None,
            service_id=None,
            source_tool="nuclei",
            vuln_type="reflected_xss",
            severity="high",
            description="XSS in search parameter (detected by nuclei)",
            parameter="q",
            fingerprint=fp,
        )

        assert f1.id == f2.id, "Same fingerprint should return same finding"
        print("PASS: fingerprint_dedup")
    finally:
        db.close()
        teardown_test_db()


def test_auto_approve_recon():
    assert check_recon_auto_approved("scan", "low") == True
    assert check_recon_auto_approved("exploit_attempt", "high") == False
    assert check_recon_auto_approved("credential_test", "medium") == False
    print("PASS: auto_approve_logic")


if __name__ == "__main__":
    test_scope_gate_blocks_unauthorized()
    test_scope_gate_blocks_outside_window()
    test_scope_gate_requires_approved()
    test_fingerprint_dedup()
    test_auto_approve_recon()
    print("\nAll tests passed!")
