/**
 * Tipos compartilhados para identificação do autor de laudos forenses.
 * Quatro modos: Perito Oficial × Policial × Operador do Direito × Vítima.
 *
 * NOTA: para evitar migration nova, os modos novos reaproveitam colunas
 * existentes em `forensic_author_profile`:
 *   - operador_direito: matricula=OAB nº, unidade=UF da OAB,
 *                       orgao_instituicao=escritório/órgão, cargo_funcao=cargo
 *   - vitima:           matricula=documento (CPF/RG), unidade=contato
 */

export type AuthorMode = 'perito' | 'policial' | 'operador_direito' | 'vitima';

export interface ForensicAuthor {
  mode: AuthorMode;
  fullName: string;
  documentNumber?: string;   // nº do laudo / relatório / registro
  localEmissao?: string;
  // perito
  registroProfissional?: string;
  // perito + operador_direito (escritório/órgão)
  orgaoInstituicao?: string;
  // policial + operador_direito (OAB nº) + vitima (documento)
  matricula?: string;
  // policial + operador_direito
  cargoFuncao?: string;
  // policial + operador_direito (UF) + vitima (contato)
  unidade?: string;
}

export const MODE_LABEL: Record<AuthorMode, string> = {
  perito: 'Sou Perito Oficial',
  policial: 'Sou Policial / Investigador',
  operador_direito: 'Sou Operador do Direito',
  vitima: 'Sou Vítima / Cidadão',
};

export const MODE_BADGE: Record<AuthorMode, string> = {
  perito: 'Perito Oficial',
  policial: 'Policial / Investigador',
  operador_direito: 'Operador do Direito',
  vitima: 'Vítima / Declarante',
};

export const TITLE_BY_MODE: Record<AuthorMode, string> = {
  perito: 'Laudo Pericial',
  policial: 'Relatório Técnico de Análise Forense',
  operador_direito: 'Relatório Técnico para Instrução Processual',
  vitima: 'Relato de Evidência da Vítima',
};

export const FILE_PREFIX_BY_MODE: Record<AuthorMode, string> = {
  perito: 'Relatorio_Evidencia',
  policial: 'Relatorio_Evidencia',
  operador_direito: 'Relatorio_Evidencia',
  vitima: 'Relatorio_Evidencia',
};

export const OPERATIONAL_DISCLAIMER =
  'Este documento é um relatório técnico operacional e não substitui laudo pericial oficial produzido por perito habilitado.';

export const LEGAL_OPERATOR_DISCLAIMER =
  'Documento técnico produzido por operador do direito para fins de instrução processual. Não constitui laudo pericial oficial; recomenda-se ratificação por perito habilitado quando exigido.';

export const VICTIM_DISCLAIMER =
  'Relato de evidência produzido pela própria vítima, sem caráter pericial. Destina-se a instruir boletim de ocorrência, denúncia ou pedido investigativo perante a autoridade competente.';

export function disclaimerForMode(mode: AuthorMode): string | null {
  if (mode === 'policial') return OPERATIONAL_DISCLAIMER;
  if (mode === 'operador_direito') return LEGAL_OPERATOR_DISCLAIMER;
  if (mode === 'vitima') return VICTIM_DISCLAIMER;
  return null;
}

export function isAuthorValid(a: ForensicAuthor | null | undefined): boolean {
  if (!a) return false;
  if (!a.fullName?.trim()) return false;
  if (a.mode === 'perito') return !!a.registroProfissional?.trim();
  if (a.mode === 'policial') return !!a.matricula?.trim();
  if (a.mode === 'operador_direito') {
    // OAB OU cargo/função (defensor, MP, juiz nem sempre tem OAB)
    return !!(a.matricula?.trim() || a.cargoFuncao?.trim());
  }
  if (a.mode === 'vitima') return true; // só nome é exigido
  return false;
}

/** Rótulo do bloco "Identificação do …" conforme o modo. */
export const AUTHOR_BLOCK_TITLE: Record<AuthorMode, string> = {
  perito: 'Perito',
  policial: 'Operador',
  operador_direito: 'Operador do Direito',
  vitima: 'Declarante',
};

/** Rótulo do campo de número de documento conforme o modo. */
export function documentNumberLabel(mode: AuthorMode): string {
  if (mode === 'perito') return 'Nº do laudo';
  if (mode === 'policial') return 'Nº do relatório';
  if (mode === 'operador_direito') return 'Nº do documento';
  return 'Nº do registro / B.O.';
}

/** Linhas tabulares (label → valor) para exibir no PDF/Bloco. Pula valores vazios. */
export function getAuthorRows(author: ForensicAuthor): Array<[string, string]> {
  const rows: Array<[string, string]> = [
    ['Modo de emissão', MODE_BADGE[author.mode]],
    ['Nome completo', author.fullName || '—'],
  ];
  switch (author.mode) {
    case 'perito':
      rows.push(['Registro profissional', author.registroProfissional || '—']);
      if (author.orgaoInstituicao) rows.push(['Órgão / instituição', author.orgaoInstituicao]);
      break;
    case 'policial':
      rows.push(['Matrícula funcional', author.matricula || '—']);
      if (author.cargoFuncao) rows.push(['Cargo / função', author.cargoFuncao]);
      if (author.unidade) rows.push(['Unidade', author.unidade]);
      break;
    case 'operador_direito':
      if (author.cargoFuncao) rows.push(['Cargo / função', author.cargoFuncao]);
      if (author.matricula) {
        const uf = author.unidade ? `/${author.unidade}` : '';
        rows.push(['OAB', `${author.matricula}${uf}`]);
      }
      if (author.orgaoInstituicao) rows.push(['Escritório / órgão', author.orgaoInstituicao]);
      break;
    case 'vitima':
      if (author.matricula) rows.push(['Documento de identidade', author.matricula]);
      if (author.unidade) rows.push(['Contato', author.unidade]);
      break;
  }
  if (author.documentNumber) {
    rows.push([documentNumberLabel(author.mode), author.documentNumber]);
  }
  if (author.localEmissao) rows.push(['Local de emissão', author.localEmissao]);
  return rows;
}

/** Segunda linha da assinatura (abaixo do nome). */
export function getSignatureSubline(author: ForensicAuthor): string {
  switch (author.mode) {
    case 'perito':
      return [author.registroProfissional || 'Perito Oficial', author.orgaoInstituicao]
        .filter(Boolean).join(' · ');
    case 'policial':
      return [
        author.cargoFuncao,
        author.matricula && `Matrícula ${author.matricula}`,
        author.unidade,
      ].filter(Boolean).join(' · ') || 'Policial / Investigador';
    case 'operador_direito': {
      const oab = author.matricula
        ? `OAB ${author.matricula}${author.unidade ? `/${author.unidade}` : ''}`
        : '';
      return [author.cargoFuncao || 'Operador do Direito', oab, author.orgaoInstituicao]
        .filter(Boolean).join(' · ');
    }
    case 'vitima':
      return ['Declarante (Vítima)', author.matricula && `Doc.: ${author.matricula}`]
        .filter(Boolean).join(' · ');
  }
}

