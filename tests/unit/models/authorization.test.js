import { describe, it, expect, vi, beforeEach } from 'vitest';
import auth from 'models/authorization'; // Assumindo que seu arquivo se chama 'authorization.js'
import { ForbiddenError, ValidationError } from 'errors';
import availableFeatures from 'models/user-features.js';

// Vamos extrair a função que queremos testar
const { filterInput } = auth;

// Mock das dependências externas
vi.mock('./models/user-features', () => ({
  default: new Set(['create:user', 'update:user', 'update:user:others', 'ban:user', 'create:content:text_root']),
}));

vi.mock('./errors', () => ({
  ValidationError: class ValidationError extends Error {
    constructor({ message }) {
      super(message);
      this.name = 'ValidationError';
    }
  },
  ForbiddenError: class ForbiddenError extends Error {
    constructor({ message }) {
      super(message);
      this.name = 'ForbiddenError';
    }
  },
}));

// Mock do validator (usado em outras funções, mas bom ter)
vi.mock('./models/validator.js', () => ({
  default: vi.fn((data) => data), // Simplesmente retorna o que recebe
}));

// --- Início dos Testes ---

describe('filterInput()', () => {
  // Usuário padrão para testes de permissão
  const mockUser = {
    id: 1,
    features: ['create:user', 'update:user'],
  };

  describe('Validação de Argumentos', () => {
    it('deve lançar ValidationError se o "user" for nulo ou inválido', () => {
      const input = { username: 'test' };
      //
      expect(() => filterInput(null, 'create:user', input)).toThrow(ValidationError);
      //
      expect(() => filterInput(null, 'create:user', input)).toThrow('Nenhum "user" foi especificado');
      //
      expect(() => filterInput({}, 'create:user', input)).toThrow('"user" não possui "features"');
    });

    it('deve lançar ValidationError se a "feature" for nula', () => {
      //
      expect(() => filterInput(mockUser, null, {})).toThrow(ValidationError);
      //
      expect(() => filterInput(mockUser, null, {})).toThrow('Nenhuma "feature" foi especificada');
    });

    it('deve lançar ValidationError se a "feature" não estiver em "availableFeatures"', () => {
      //
      expect(() => filterInput(mockUser, 'feature_inexistente', {})).toThrow(ValidationError);
      //
      expect(() => filterInput(mockUser, 'feature_inexistente', {})).toThrow('A feature utilizada não está disponível');
    });

    it('deve lançar ValidationError se o "input" for nulo', () => {
      //
      expect(() => filterInput(mockUser, 'create:user', null)).toThrow(ValidationError);
      //
      expect(() => filterInput(mockUser, 'create:user', null)).toThrow('Nenhum "input" foi especificado');
    });
  });

  describe('Lógica de Whitelist (Anti-Mass Assignment)', () => {
    it('deve filtrar corretamente para "create:user"', () => {
      const input = {
        username: 'novo_usuario',
        email: 'email@teste.com',
        password: 'senha123',
        // Campos maliciosos
        is_admin: true,
        tabcoins: 9999,
      };

      //
      const filtered = filterInput(mockUser, 'create:user', input);

      expect(filtered).toEqual({
        username: 'novo_usuario',
        email: 'email@teste.com',
        password: 'senha123',
      });
      //
      expect(filtered).not.toHaveProperty('is_admin');
      expect(filtered).not.toHaveProperty('tabcoins');
    });

    it('deve filtrar corretamente para "update:user" quando o usuário é o dono', () => {
      const targetResource = { id: 1 }; // O ID do recurso é o mesmo do usuário
      const input = {
        username: 'nome_atualizado',
        description: 'nova bio',
        // Campos maliciosos
        is_admin: true,
        features: ['ban:user'],
      };

      //
      const filtered = filterInput(mockUser, 'update:user', input, targetResource);

      expect(filtered).toEqual({
        username: 'nome_atualizado',
        description: 'nova bio',
        //
        email: undefined, // Estes campos estão na whitelist, mas não no input
        password: undefined,
        notifications: undefined,
      });
      //
      expect(filtered).not.toHaveProperty('is_admin');
      expect(filtered).not.toHaveProperty('features');
    });

    it('deve filtrar corretamente para "ban:user"', () => {
      const userAdmin = { id: 2, features: ['ban:user'] };
      const input = {
        ban_type: 'permanent',
        // Campo não permitido
        reason: 'spam',
      };

      //
      const filtered = filterInput(userAdmin, 'ban:user', input);

      expect(filtered).toEqual({
        ban_type: 'permanent',
      });
      //
      expect(filtered).not.toHaveProperty('reason');
    });
  });

  describe('Verificação de Permissão (can())', () => {
    it('deve retornar um objeto vazio se o usuário não tiver a feature', () => {
      const userSemFeature = { id: 1, features: ['outra:feature'] };
      const input = { username: 'test', password: '123' };

      //
      const filtered = filterInput(userSemFeature, 'create:user', input);
      //
      expect(filtered).toEqual({});
    });

    it('deve retornar um objeto vazio se "can()" falhar (ex: atualizando perfil de outro usuário)', () => {
      const targetResource = { id: 2 }; // ID do recurso é DIFERENTE do usuário
      const input = { username: 'novo_nome' };

      // mockUser (id: 1) tem a feature 'update:user'
      // Mas can() irá falhar porque user.id !== resource.id
      const filtered = filterInput(mockUser, 'update:user', input, targetResource);
      //
      expect(filtered).toEqual({});
    });
  });

  describe('Limpeza de undefined', () => {
    it('deve remover chaves com valor "undefined" do resultado final', () => {
      const input = {
        username: 'usuario',
        email: undefined, // Este deve ser removido
        password: '123',
        description: undefined, // Este também
      };

      //
      const filtered = filterInput(mockUser, 'create:user', input);

      // O filtro para 'create:user' só inclui username, email, password
      // email será undefined e será removido pelo JSON.parse/stringify
      expect(filtered).toEqual({
        username: 'usuario',
        password: '123',
      });
      //
      expect(filtered).not.toHaveProperty('email');
      expect(filtered).not.toHaveProperty('description');
      expect(Object.keys(filtered)).not.toContain('email');
    });
  });
});
