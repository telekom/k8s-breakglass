import { decideRejectOrWithdraw } from './sessionActions';

describe('sessionActions', () => {
  it('returns withdraw when current user equals owner', () => {
    const bg = { spec: { user: 'me@example.com' } };
    expect(decideRejectOrWithdraw('me@example.com', bg)).toBe('withdraw');
  });

  it('returns reject for different user', () => {
    const bg = { spec: { user: 'other@example.com' } };
    expect(decideRejectOrWithdraw('me@example.com', bg)).toBe('reject');
  });
});
