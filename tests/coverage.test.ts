import { describe, expect, it } from 'vitest';
import { studyCoverage } from '../src/coverage';
import type { CertificateRecord } from '../src/model';
const instant = (day:number)=>new Date(Date.UTC(2030,0,day));
const record = (start:number,end:number,name='api.example.test') => ({dnsNames:[name],notBefore:instant(start).toISOString(),notAfter:instant(end).toISOString()}) as CertificateRecord;
describe('declared window sweep',()=>{
  it('merges overlap and boundary-sharing rotations without double-counting',()=>{
    const result=studyCoverage([record(8,20),record(1,10),record(20,31),record(4,6)],'API.EXAMPLE.TEST',instant(1),instant(31));
    expect(result.covered).toEqual([{start:instant(1).getTime(),end:instant(31).getTime()}]);
    expect(result.gaps).toEqual([]);
  });
  it('finds initial, interior and trailing gaps with clipping',()=>{
    const result=studyCoverage([record(5,10),record(15,20)],'api.example.test',instant(1),instant(31));
    expect(result.gaps).toEqual([{start:+instant(1),end:+instant(5)},{start:+instant(10),end:+instant(15)},{start:+instant(20),end:+instant(31)}]);
    expect(studyCoverage([record(1,31)],'api.example.test',instant(5),instant(20)).covered).toEqual([{start:+instant(5),end:+instant(20)}]);
  });
  it('does not infer wildcard hostname matching or use unrelated certificates',()=>{
    const result=studyCoverage([record(1,31,'*.example.test')],'api.example.test',instant(1),instant(31));
    expect(result.certificateCount).toBe(0);expect(result.covered).toEqual([]);expect(result.gaps).toHaveLength(1);
  });
  it('rejects inverted study ranges and handles an empty register',()=>{
    expect(()=>studyCoverage([],'example.test',instant(31),instant(1))).toThrow();
    expect(studyCoverage([],'example.test',instant(1),instant(31)).gaps).toHaveLength(1);
  });
});
