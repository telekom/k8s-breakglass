import { mount } from '@vue/test-utils';
import BreakglassSessionCard from '@/components/BreakglassSessionCard.vue';

describe('BreakglassSessionCard', () => {
  const baseSession = (overrides: any = {}) => ({
    spec: { grantedGroup: 'g', user: overrides.user || 'owner@example.com', cluster: 'c' },
    // retainedUntil in future so actions display
    status: { state: 'Approved', expiresAt: new Date(Date.now() + 3600 * 1000).toISOString(), approvedAt: new Date().toISOString(), retainedUntil: new Date(Date.now() + 3600 * 1000).toISOString() },
    metadata: { name: overrides.name || 's1', creationTimestamp: new Date().toISOString() },
    ...overrides,
  });

  it('shows Drop when current user is owner', () => {
    const wrapper = mount(BreakglassSessionCard as any, {
      global: {
        stubs: {
          'scale-button': {
            template: '<button><slot/></button>',
          },
          'scale-card': {
            template: '<div><slot/></div>',
          },
        },
      },
      props: {
        breakglass: baseSession({ user: 'me@example.com' }),
        time: Date.now(),
        currentUserEmail: 'me@example.com',
      },
    });

    const btnByText = wrapper.findAll('button').find((b: any) => b.text() === 'Drop');
    expect(btnByText).toBeTruthy();
  });

  it('shows Reject when current user is not owner', () => {
    const wrapper = mount(BreakglassSessionCard as any, {
      global: {
        stubs: {
          'scale-button': {
            template: '<button><slot/></button>',
          },
          'scale-card': {
            template: '<div><slot/></div>',
          },
        },
      },
      props: {
        breakglass: baseSession({ user: 'owner@example.com' }),
        time: Date.now(),
        currentUserEmail: 'other@example.com',
      },
    });

    const btnByText = wrapper.findAll('button').find((b: any) => b.text() === 'Reject');
    expect(btnByText).toBeTruthy();
  });
});
