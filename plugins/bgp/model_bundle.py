"""
BGP Model Bundle — Production Redesign
=======================================

Changes vs original:
- `scaler_meta` is now Optional[Any] because it belongs to the stacking
  ensemble path (Logistic Regression meta-learner) and is not used by the
  RandomForest inference path.  Making it optional lets the loader work even
  if only the RF artefacts are present.
- Added `n_features` property for fast validation.
- `scaler_meta` is retained in the bundle so that future stacking ensemble
  support can be added without changing the loader interface.

Python 3.12 · scikit-learn 1.6.1
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True, frozen=True)
class BGPModelBundle:
    """
    Loaded BGP model artefacts.

    Attributes
    ----------
    model:
        Trained RandomForestClassifier (or compatible sklearn estimator).
        Expects scaled input: scaler_main.transform(X_raw).

    scaler_main:
        StandardScaler fit on the 47-feature balanced training dataset.
        Must be applied to every raw feature vector before model.predict().

    scaler_meta:
        StandardScaler for the stacking ensemble meta-learner.
        Not used in the standard RF inference path.
        May be None if the stacking artefact is absent.

    feature_columns:
        Ordered list of 47 feature names.
        Defines the column order expected by scaler_main and model.
    """

    model:           Any
    scaler_main:     Any
    scaler_meta:     Any | None
    feature_columns: list[str]

    @property
    def n_features(self) -> int:
        """Number of features expected by the model."""
        return len(self.feature_columns)