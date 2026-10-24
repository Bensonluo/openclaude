import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { SandboxManager as BaseSandboxManager } from '@anthropic-ai/sandbox-runtime'
import { mkdir, mkdtemp, rm, writeFile } from 'fs/promises'
import { tmpdir } from 'os'
import { join, resolve, sep } from 'path'
import {
  getCwdState,
  getOriginalCwd,
  setCwdState,
  setOriginalCwd,
} from '../../bootstrap/state.js'
import { snapshotEnv } from '../../test/envSnapshot.js'
import {
  acquireSharedMutationLock,
  releaseSharedMutationLock,
} from '../../test/sharedMutationLock.js'
import { getSettingsForSource } from '../settings/settings.js'
import {
  resetSettingsCache,
  setCachedSettingsForSource,
} from '../settings/settingsCache.js'
import { SettingsSchema, type SettingsJson } from '../settings/types.js'
import {
  convertToSandboxRuntimeConfig,
  SandboxManager,
  SandboxRuntimeConfigSchema,
} from './sandbox-adapter.js'

describe('convertToSandboxRuntimeConfig', () => {
  let restoreEnv: () => void
  let previousOriginalCwd: string
  let previousCwd: string
  let tempRoot: string
  let activeCwd: string

  beforeEach(async () => {
    await acquireSharedMutationLock('utils/sandbox/sandbox-adapter.test.ts')

    restoreEnv = snapshotEnv(['CLAUDE_CONFIG_DIR', 'OPENCLAUDE_CONFIG_DIR'])
    previousOriginalCwd = getOriginalCwd()
    previousCwd = getCwdState()

    tempRoot = await mkdtemp(join(tmpdir(), 'openclaude-sandbox-adapter-'))
    const originalCwd = join(tempRoot, 'original-project')
    activeCwd = join(tempRoot, 'active-project')

    process.env.CLAUDE_CONFIG_DIR = join(tempRoot, 'config')
    process.env.OPENCLAUDE_CONFIG_DIR = join(tempRoot, 'openclaude-config')
    resetSettingsCache()
    setOriginalCwd(originalCwd)
    setCwdState(activeCwd)
  })

  afterEach(async () => {
    try {
      await SandboxManager.reset()
      restoreEnv()
      setOriginalCwd(previousOriginalCwd)
      setCwdState(previousCwd)
      resetSettingsCache()
      await rm(tempRoot, { recursive: true, force: true })
    } finally {
      releaseSharedMutationLock()
    }
  })

  test('denies canonical OpenClaude settings files in changed cwd', () => {
    const config = convertToSandboxRuntimeConfig({} as SettingsJson)

    expect(config.filesystem.denyWrite).toContain(
      resolve(activeCwd, '.openclaude', 'settings.json'),
    )
    expect(config.filesystem.denyWrite).toContain(
      resolve(activeCwd, '.openclaude', 'settings.local.json'),
    )
  })

  test('denies legacy Claude config surfaces in original and changed cwd', () => {
    const config = convertToSandboxRuntimeConfig({} as SettingsJson)

    for (const cwd of [getOriginalCwd(), activeCwd]) {
      expect(config.filesystem.denyWrite).toContain(
        resolve(cwd, '.claude'),
      )
    }
  })

  test('denies legacy Claude config surfaces from CLAUDE_CONFIG_DIR', () => {
    const config = convertToSandboxRuntimeConfig({} as SettingsJson)
    const configDir = process.env.CLAUDE_CONFIG_DIR!

    expect(config.filesystem.denyWrite).toContain(resolve(configDir))
  })

  test('root deny covers non-settings legacy Claude state', () => {
    const config = convertToSandboxRuntimeConfig({} as SettingsJson)

    const representativeLegacyPaths = [
      resolve(getOriginalCwd(), '.claude', 'CLAUDE.md'),
      resolve(activeCwd, '.claude', 'credentials.json'),
      resolve(process.env.CLAUDE_CONFIG_DIR!, 'plugins', 'plugin.json'),
      resolve(process.env.CLAUDE_CONFIG_DIR!, 'scheduled-tasks', 'task.json'),
    ]

    for (const legacyPath of representativeLegacyPaths) {
      expect(
        config.filesystem.denyWrite.some(
          deniedRoot =>
            legacyPath === deniedRoot ||
            legacyPath.startsWith(`${deniedRoot}${sep}`),
        ),
      ).toBe(true)
    }
  })

  test('maps validated settings to the runtime network and process policy', () => {
    const settings = SettingsSchema().parse({
      permissions: {
        allow: ['WebFetch(domain:api.example.com:443)'],
        deny: ['WebFetch(domain:blocked.example.com)', 'WebFetch(domain:*:22)'],
      },
      sandbox: {
        network: {
          allowedDomains: ['*.example.org'],
          allowUnixSockets: ['/var/run/example.sock'],
          allowAllUnixSockets: false,
          allowLocalBinding: false,
          httpProxyPort: 8080,
          socksProxyPort: 1080,
        },
        ignoreViolations: { '*': ['/dev/example'] },
        enableWeakerNestedSandbox: false,
        enableWeakerNetworkIsolation: false,
        ripgrep: { command: 'rg', args: ['--hidden'] },
      },
    })
    const config = SandboxRuntimeConfigSchema.parse(
      convertToSandboxRuntimeConfig(settings),
    )

    expect(config.network).toEqual({
      allowedDomains: ['*.example.org', 'api.example.com:443'],
      deniedDomains: ['blocked.example.com', '*:22'],
      allowUnixSockets: ['/var/run/example.sock'],
      allowAllUnixSockets: false,
      allowLocalBinding: false,
      httpProxyPort: 8080,
      socksProxyPort: 1080,
    })
    expect(config.ignoreViolations).toEqual({ '*': ['/dev/example'] })
    expect(config.enableWeakerNestedSandbox).toBe(false)
    expect(config.enableWeakerNetworkIsolation).toBe(false)
    expect(config.ripgrep).toEqual({ command: 'rg', args: ['--hidden'] })
    expect(config.filesystem.disabled).toBeUndefined()
    expect(config.allowNestedUserNamespaces).toBeUndefined()
    expect(config.credentials).toBeUndefined()
    expect(config.windows).toBeUndefined()

    BaseSandboxManager.updateConfig(config)
    expect(SandboxManager.getNetworkRestrictionConfig()).toEqual({
      allowedHosts: ['*.example.org', 'api.example.com:443'],
      deniedHosts: ['blocked.example.com', '*:22'],
    })
    expect(SandboxManager.getAllowUnixSockets()).toEqual(['/var/run/example.sock'])
    expect(SandboxManager.getAllowLocalBinding()).toBe(false)
    expect(SandboxManager.getIgnoreViolations()).toEqual({ '*': ['/dev/example'] })
    expect(SandboxManager.getEnableWeakerNestedSandbox()).toBe(false)
  })

  test('loads filesystem rules from disk with their source path semantics', async () => {
    const configDir = process.env.OPENCLAUDE_CONFIG_DIR!
    await mkdir(configDir, { recursive: true })
    await writeFile(join(configDir, 'settings.json'), JSON.stringify({
      permissions: {
        allow: ['Edit(/editable/**)'],
        deny: ['Read(//private/**)', 'Edit(/locked/**)'],
      },
      sandbox: {
        filesystem: {
          allowWrite: ['./build'],
          denyWrite: [join(tempRoot, 'protected')],
          denyRead: ['./secrets'],
          allowRead: ['./secrets/public'],
        },
      },
    }))
    resetSettingsCache()
    const settings = getSettingsForSource('userSettings')!
    expect(settings.sandbox?.filesystem?.allowWrite).toEqual(['./build'])
    const config = SandboxRuntimeConfigSchema.parse(
      convertToSandboxRuntimeConfig(settings),
    )
    BaseSandboxManager.updateConfig(config)

    const read = SandboxManager.getFsReadConfig()
    const write = SandboxManager.getFsWriteConfig()
    expect(read.denyOnly).toContain('/private')
    expect(read.denyOnly).toContain(join(configDir, 'secrets'))
    expect(read.allowWithinDeny).toContain(join(configDir, 'secrets/public'))
    expect(write.allowOnly).toContain(join(configDir, 'editable'))
    expect(write.allowOnly).toContain(join(configDir, 'build'))
    expect(write.denyWithinAllow).toContain(join(configDir, 'locked'))
    expect(write.denyWithinAllow).toContain(join(tempRoot, 'protected'))
    expect(write.denyWithinAllow).toContain(
      join(activeCwd, '.openclaude', 'settings.json'),
    )
  })

  test('keeps managed domain and read exceptions exclusive without dropping denies', () => {
    setCachedSettingsForSource('policySettings', SettingsSchema().parse({
      permissions: { allow: ['WebFetch(domain:managed.example.com)'] },
      sandbox: {
        network: {
          allowManagedDomainsOnly: true,
          allowedDomains: ['policy.example.com'],
        },
        filesystem: {
          allowManagedReadPathsOnly: true,
          allowRead: [join(tempRoot, 'policy-public')],
        },
      },
    }))
    const userSettings = SettingsSchema().parse({
      permissions: {
        allow: ['WebFetch(domain:user.example.com)'],
        deny: ['WebFetch(domain:blocked.example.com)'],
      },
      sandbox: {
        network: { allowedDomains: ['extra.example.com'] },
        filesystem: {
          allowRead: [join(tempRoot, 'user-public')],
          denyRead: [join(tempRoot, 'secrets')],
        },
      },
    })
    setCachedSettingsForSource('userSettings', userSettings)
    const config = SandboxRuntimeConfigSchema.parse(
      convertToSandboxRuntimeConfig(userSettings),
    )

    expect(config.network.allowedDomains).toEqual([
      'policy.example.com', 'managed.example.com',
    ])
    expect(config.network.deniedDomains).toEqual(['blocked.example.com'])
    expect(config.filesystem.allowRead).toEqual([join(tempRoot, 'policy-public')])
    expect(config.filesystem.denyRead).toContain(join(tempRoot, 'secrets'))
  })

  test('preserves an empty network allowlist through the runtime adapter', () => {
    const config = SandboxRuntimeConfigSchema.parse(
      convertToSandboxRuntimeConfig(SettingsSchema().parse({})),
    )
    BaseSandboxManager.updateConfig(config)

    expect(SandboxManager.getNetworkRestrictionConfig()).toEqual({
      allowedHosts: [],
    })
    expect(SandboxManager.getAllowLocalBinding()).toBeUndefined()
    expect(SandboxManager.getAllowUnixSockets()).toBeUndefined()
  })

  test('exposes sanitized violation events and subscriptions through the adapter', () => {
    const store = SandboxManager.getSandboxViolationStore()
    const timestamp = new Date('2026-01-01T00:00:00Z')
    const count = store.getTotalCount()
    const lines: string[][] = []
    const unsubscribe = store.subscribe(events => {
      lines.push(events.map(event => event.line))
    })
    try {
      store.addViolation({
        line: 'deny\n<file-write>', command: 'touch blocked', timestamp,
      })
      expect(store.getViolations().at(-1)).toEqual({
        line: 'deny file-write', command: 'touch blocked', timestamp,
      })
      expect(store.getTotalCount()).toBe(count + 1)
      expect(lines.at(-1)).toEqual(['deny file-write'])
    } finally {
      unsubscribe()
      store.clear()
    }
  })
})
