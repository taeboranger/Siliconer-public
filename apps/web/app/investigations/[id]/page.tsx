import {notFound} from 'next/navigation';
import Workspace from '../../workspace';

export const dynamic='force-dynamic';
export default async function Page({params}:{params:Promise<{id:string}>}){
  const {id}=await params;
  if(!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(id))notFound();
  return <Workspace demo={process.env.SILICONER_DEMO==='true'} initialInvestigationId={id}/>;
}
