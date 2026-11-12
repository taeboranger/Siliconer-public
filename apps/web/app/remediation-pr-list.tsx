export type RemediationPr={repository:string;number:number;title:string;path:string};

export default function RemediationPrList({items}:{items:RemediationPr[]}){
  if(!items.length)return null;
  return <ul className="remediation-pr-list">
    {items.map(pr=><li key={`${pr.repository}#${pr.number}`}>
      <a href={`https://github.com/${pr.repository}/pull/${pr.number}`} target="_blank" rel="noreferrer">
        {pr.title} · {pr.repository} #{pr.number} ↗
      </a>
      <small className="muted block">{pr.path}</small>
    </li>)}
  </ul>;
}
