# dcf/optimizer_bandit.py
import json
import math
import os
from typing import Dict, List, Tuple
import threading

# Minimal LinUCB: one model per action (recipe_id), context as dense vector
class LinUCB:
    def __init__(self, d: int, alpha: float = 0.8):
        self.d = d
        self.alpha = alpha
        self.actions = {}  # recipe_id -> {"A": I_d, "b": zeros(d)}
        self._lock = threading.Lock()

    def _init_action(self, a: str):
        import numpy as np
        self.actions[a] = {
            "A": np.eye(self.d),
            "b": np.zeros((self.d, 1)),
        }

    def score(self, a: str, x) -> float:
        import numpy as np
        if a not in self.actions:
            self._init_action(a)
        A = self.actions[a]["A"]
        b = self.actions[a]["b"]
        A_inv = np.linalg.inv(A)
        theta = A_inv @ b
        x = x.reshape((self.d, 1))
        p = float((theta.T @ x) + self.alpha * math.sqrt(x.T @ A_inv @ x))
        return p

    def update(self, a: str, x, reward: float):
        import numpy as np
        if a not in self.actions:
            self._init_action(a)
        A = self.actions[a]["A"]
        b = self.actions[a]["b"]
        x = x.reshape((self.d, 1))
        with self._lock:
            self.actions[a]["A"] = A + (x @ x.T)
            self.actions[a]["b"] = b + reward * x

class BanditOptimizer:
    """
    Wraps LinUCB for choosing among candidate recipes given feature vector x.
    Persists minimal state to disk so learning survives restarts.
    """
    def __init__(self, d: int, alpha: float = 0.8, state_path: str = "bandit_state.json"):
        self.lucb = LinUCB(d=d, alpha=alpha)
        self.state_path = state_path
        self._load()

    def _load(self):
        if not os.path.exists(self.state_path):
            return
        try:
            with open(self.state_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            import numpy as np
            for a, dct in payload.items():
                A = np.array(dct["A"])
                b = np.array(dct["b"]).reshape((self.lucb.d, 1))
                self.lucb.actions[a] = {"A": A, "b": b}
        except Exception:
            pass

    def _save(self):
        try:
            payload = {}
            for a, dct in self.lucb.actions.items():
                payload[a] = {"A": dct["A"].tolist(), "b": dct["b"].reshape(-1).tolist()}
            with open(self.state_path, "w", encoding="utf-8") as f:
                json.dump(payload, f)
        except Exception:
            pass

    def choose(self, actions: List[str], x_vec) -> Tuple[str, Dict[str, float]]:
        scores = {a: self.lucb.score(a, x_vec) for a in actions}
        chosen = max(scores.items(), key=lambda kv: kv[1])[0]
        return chosen, scores

    def learn(self, action: str, x_vec, reward: float):
        self.lucb.update(action, x_vec, reward)
        self._save()
