from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

class InvestigationWorkspace:
    """Persistent analyst workspace for saved searches, bookmarks and sessions."""
    def __init__(self,path="data/investigation_workspace.json"):
        self.path=Path(path); self.data={"saved_searches":[],"bookmarks":[],"sessions":[]}; self.load()
    def load(self):
        if self.path.exists():
            try:
                d=json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(d,dict): self.data.update(d)
            except Exception: pass
        return self.data
    def save(self):
        self.path.parent.mkdir(parents=True,exist_ok=True)
        self.path.write_text(json.dumps(self.data,indent=2,ensure_ascii=False),encoding="utf-8")
    def add_saved_search(self,name,field,query):
        item={"name":str(name).strip(),"field":str(field),"query":str(query),"created_at":datetime.now(timezone.utc).isoformat(timespec="seconds")}
        self.data["saved_searches"]=[x for x in self.data["saved_searches"] if x.get("name")!=item["name"]]
        self.data["saved_searches"].append(item); self.save(); return item
    def add_bookmark(self,evidence_id,reason=""):
        item={"evidence_id":str(evidence_id),"reason":str(reason),"created_at":datetime.now(timezone.utc).isoformat(timespec="seconds")}
        if not any(x.get("evidence_id")==item["evidence_id"] for x in self.data["bookmarks"]):
            self.data["bookmarks"].append(item); self.save()
        return item
    def snapshot(self,case_id,log_file,filter_field,query):
        item={"case_id":case_id,"log_file":log_file,"filter_field":filter_field,"query":query,"created_at":datetime.now(timezone.utc).isoformat(timespec="seconds")}
        self.data["sessions"].append(item); self.save(); return item
