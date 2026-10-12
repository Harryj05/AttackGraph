from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from db.database import get_db
from api.schemas import CalibrationReportResponse
from graph.calibration import compute_calibration

router = APIRouter(prefix="/calibration", tags=["calibration"])


@router.get("", response_model=CalibrationReportResponse)
def get_global_calibration(include_synthetic: bool = False, db: Session = Depends(get_db)):
    """
    GET /calibration
    Cross-scan aggregate offline calibration report (Section 11.5).
    Evaluates stated edge confidence against observed verification outcomes across all scans.
    """
    report = compute_calibration(db, scan_ids=None, include_synthetic=include_synthetic)
    return report
