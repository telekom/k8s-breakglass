import BreakglassService from './breakglass';
import axios from 'axios';

jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('BreakglassService', () => {
  const fakeAuth = { getAccessToken: async () => 'fake-token' } as any;
  let service: BreakglassService;
  let mockClient: any;

  beforeEach(() => {
    mockClient = {
      get: jest.fn(),
      interceptors: {
        request: { use: jest.fn() },
        response: { use: jest.fn() },
      },
    };
    (mockedAxios.create as jest.Mock).mockReturnValue(mockClient);
    service = new BreakglassService(fakeAuth);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('maps withdrawn and rejected sessions using status.state', async () => {
    mockClient.get
      .mockResolvedValueOnce({ data: [
        { metadata: { name: 'withdrawn1' }, spec: { grantedGroup: 'g1', cluster: 'c1' }, status: { state: 'Withdrawn' } },
      ] })
      .mockResolvedValueOnce({ data: [
        { metadata: { name: 'rejected1' }, spec: { grantedGroup: 'g2', cluster: 'c2' }, status: { state: 'Rejected' } },
      ] });

    const sessions = await service.fetchHistoricalSessions();
    expect(sessions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: 'withdrawn1', state: 'Withdrawn' }),
        expect.objectContaining({ name: 'rejected1', state: 'Rejected' }),
      ])
    );
  });

  it('normalizes active sessions so getBreakglasses() can match them', async () => {
    // fetchAvailableEscalations -> returns one available escalation
    mockClient.get
      .mockResolvedValueOnce({ data: [ { spec: { allowed: { groups: ['test-user'], clusters: ['c1'] }, escalatedGroup: 'g1', maxValidFor: '1h' } } ] })
      // fetchActiveSessions -> returns approved session with nested metadata/spec/status
      .mockResolvedValueOnce({ data: [ { metadata: { name: 's1' }, spec: { grantedGroup: 'g1', cluster: 'c1' }, status: { expiresAt: new Date().toISOString(), state: 'Approved' } } ] })
      // fetchMyOutstandingRequests -> none
      .mockResolvedValueOnce({ data: [] })
      // fetchHistoricalSessions -> rejected and withdrawn (two sequential GETs inside helper)
      .mockResolvedValueOnce({ data: [] })
      .mockResolvedValueOnce({ data: [] });

    const service = new BreakglassService({ getAccessToken: async () => 't' } as any);
    const res = await service.getBreakglasses();
    expect(res).toHaveLength(1);
  const first: any = res[0];
  expect(first.sessionActive).not.toBeNull();
  expect(first.sessionActive.metadata).toBeDefined();
  expect(first.sessionActive.spec).toBeDefined();
  });

  it('includes provided reason when requesting breakglass for test-user', async () => {
    const fakeAuth2 = { getAccessToken: async () => 'tok', getUserEmail: async () => 'test-user@example.com' } as any;
    const mockClient2: any = { post: jest.fn(), get: jest.fn(), interceptors: { request: { use: jest.fn() }, response: { use: jest.fn() } } };
    (mockedAxios.create as jest.Mock).mockReturnValueOnce(mockClient2);
    const svc = new BreakglassService(fakeAuth2);
    mockClient2.post.mockResolvedValueOnce({ status: 201 });

    const transition = { cluster: 'c1', to: 'g1', duration: 3600 } as any;
    await svc.requestBreakglass(transition, 'needed for testing');
    expect(mockClient2.post).toHaveBeenCalledWith('/breakglassSessions', expect.objectContaining({ reason: 'needed for testing', user: 'test-user@example.com' }));
  });
});
