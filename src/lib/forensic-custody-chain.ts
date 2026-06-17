/**
 * Cadeia de custódia encadeada por hash — genérica, reutilizável.
 * Cada elo carrega o hash do anterior, formando uma Merkle list que
 * detecta qualquer inserção/edição/remoção de evidências.
 *
 * Atende CPP art. 158-B/E + STJ AgRg HC 828.054/RN (rastreabilidade
 * reforçada para prova digital "facilmente alterável").
 *
 * Reexporta a implementação já validada do WhatsApp Wizard.
 */
export { CustodyChain, type CustodyStep } from './whatsapp-custody-chain';

import { CustodyChain } from './whatsapp-custody-chain';
import { generateSHA256 } from './forensic-hash';

/** Calcula a raiz Merkle simplificada (chain hash) de uma cadeia já encerrada. */
export async function computeMerkleRoot(chain: CustodyChain): Promise<string> {
  const steps = chain.getSteps();
  if (steps.length === 0) return 'EMPTY';
  const material = steps.map((s) => s.hash).join('|');
  return generateSHA256(material);
}
