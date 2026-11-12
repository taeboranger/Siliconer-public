'use client';
import {useState} from 'react';
type Row=Record<string,any>;
const labels:Record<string,string>={open:'미처리',in_progress:'처리 중',blocked:'보류',resolved:'종결'};
export default function TicketForm({ticket,save,busy}:{ticket:Row;save:(body:Row)=>Promise<any>;busy:boolean}){
  const [changes,setChanges]=useState<{status?:string;notes?:string}>({});
  const [saved,setSaved]=useState(false);
  const hasChanges=Object.keys(changes).length>0;
  return <form onSubmit={event=>{
    event.preventDefault();
    if(busy||!hasChanges)return;
    void save(changes).then(()=>{setChanges({});setSaved(true);}).catch(()=>{});
  }}>
    <label>티켓 상태<select value={changes.status??ticket.status} disabled={busy} onChange={event=>{
      const status=event.target.value;
      setChanges(previous=>({...previous,status}));setSaved(false);
    }}>{Object.entries(labels).map(([value,label])=><option key={value} value={value}>{label}</option>)}</select></label>
    <label>메모<textarea value={changes.notes??ticket.notes} maxLength={8000} disabled={busy} rows={3} onChange={event=>{
      const notes=event.target.value;
      setChanges(previous=>({...previous,notes}));setSaved(false);
    }}/></label>
    <button className="primary" disabled={busy||!hasChanges} type="submit">티켓 저장</button>
    {saved?<span role="status" className="saved">저장했습니다.</span>:null}
  </form>;
}
