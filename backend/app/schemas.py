from pydantic import BaseModel
from typing import List, Optional

class TopPrediction(BaseModel):
    label: str
    probability: float

class DetectionResult(BaseModel):
    row: int
    prediction: str
    confidence: float
    severity: str
    mitre: str
    flow_duration_ms: Optional[float] = None
    total_packets: Optional[int] = None
    flow_bytes_per_sec: Optional[float] = None
    flow_packets_per_sec: Optional[float] = None
    syn_flag_ratio: Optional[float] = None
    top_predictions: List[TopPrediction] = []

class DetectionResponse(BaseModel):
    total_records: int
    attacks_detected: int
    results: List[DetectionResult]

class EvaluationMetrics(BaseModel):
    accuracy: float
    precision: float
    recall: float
    f1_score: float

class StatsSummary(BaseModel):
    total_scans: int
    total_records_processed: int
    total_attacks_detected: int
    average_attack_ratio: float

class PerformanceSummary(BaseModel):
    total_scans: int
    average_attack_ratio: float
    max_attack_ratio: float
    min_attack_ratio: float
    recent_scans: List[float]

class ConfusionMatrixResponse(BaseModel):
    total_records: int
    true_positive: int
    true_negative: int
    false_positive: int
    false_negative: int
