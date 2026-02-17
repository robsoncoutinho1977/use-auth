export type AuthUserPayload = {
  id: number;
  idtipousuario: number;
  idcentro: number | null;
  centro: string | null;
  nomefantasia: string | null;
  idtipousuariocentro: number | null;
  nomerazao: string;
  cpfcnpj: string;
  email: string | null;
  idstatususuario: number;
};

export type AuthUserRow = AuthUserPayload & {
  senha: string | null;
};
