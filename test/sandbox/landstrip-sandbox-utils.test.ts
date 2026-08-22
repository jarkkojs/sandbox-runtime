import { afterEach, describe, expect, it } from 'bun:test'
import { binaryPath } from '@landstrip/landstrip'
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import {
  buildLandstripPolicy,
  cleanupLandstripPolicies,
  getLandstripMandatoryDenyWrite,
  wrapCommandWithLandstrip,
  writeLandstripPolicy,
} from '../../src/sandbox/landstrip-sandbox-utils.js'

describe('Landstrip sandbox utilities', () => {
  afterEach(() => cleanupLandstripPolicies())

  it('translates ASR restrictions into a Landstrip policy', () => {
    const policy = buildLandstripPolicy({
      platform: 'linux',
      cwd: '/workspace',
      shell: { exe: '/bin/bash', args: ['-c'] },
      needsNetworkRestriction: true,
      httpProxyPort: 60080,
      socksProxyPort: 60081,
      allowLocalBinding: true,
      allowUnixSockets: ['/run/example.sock'],
      readConfig: {
        denyOnly: ['/home/user/.ssh'],
        allowWithinDeny: ['/home/user/.ssh/config'],
      },
      writeConfig: {
        allowOnly: ['/workspace'],
        denyWithinAllow: ['/workspace/.env'],
      },
      mandatoryDenyWrite: ['/workspace/**/.git/hooks/**'],
      maskedFileBinds: [
        { realPath: '/home/user/token', fakePath: '/tmp/masked/token' },
      ],
    })

    expect(policy.filesystem).toEqual({
      denyRead: ['/home/user/.ssh', '/home/user/token'],
      allowRead: ['/home/user/.ssh/config'],
      allowWrite: ['/workspace'],
      denyWrite: ['/workspace/.env', '/workspace/**/.git/hooks/**'],
    })
    expect(policy.network).toEqual({
      allowNetwork: false,
      allowLocalBinding: true,
      allowAllUnixSockets: false,
      allowUnixSockets: ['/run/example.sock'],
      httpProxyPort: 60080,
      socksProxyPort: 60081,
    })
  })

  it('protects nested dangerous directory roots and their contents', () => {
    const deny = getLandstripMandatoryDenyWrite('/workspace')

    expect(deny).toContain('/workspace/**/.vscode')
    expect(deny).toContain('/workspace/**/.vscode/**')
    expect(deny).toContain('/workspace/**/.git/hooks')
    expect(deny).toContain('/workspace/**/.git/hooks/**')
  })

  it('keeps local and private destinations out of the proxy', () => {
    const invocation = wrapCommandWithLandstrip({
      landstripPath: '/usr/bin/landstrip',
      platform: 'linux',
      cwd: '/workspace',
      shell: { exe: '/bin/sh', args: ['-c'] },
      command: 'true',
      needsNetworkRestriction: true,
      httpProxyPort: 60080,
      writeConfig: { allowOnly: ['/workspace'], denyWithinAllow: [] },
    })

    expect(
      invocation.argv.find(value => value.startsWith('NO_PROXY=')),
    ).toContain('localhost')
    expect(
      invocation.argv.find(value => value.startsWith('no_proxy=')),
    ).toContain('localhost')
  })

  it('writes unique private policies and removes them together', () => {
    const policy = buildLandstripPolicy({
      platform: 'linux',
      cwd: '/workspace',
      shell: { exe: '/bin/sh', args: ['-c'] },
      needsNetworkRestriction: false,
    })
    const paths = Array.from({ length: 32 }, () => writeLandstripPolicy(policy))

    expect(new Set(paths).size).toBe(paths.length)
    for (const path of paths) {
      expect(existsSync(path)).toBe(true)
      expect(statSync(path).mode & 0o777).toBe(0o600)
    }

    const oldDirectory = dirname(paths[0]!)
    cleanupLandstripPolicies()
    expect(existsSync(oldDirectory)).toBe(false)

    const nextPath = writeLandstripPolicy(policy)
    expect(dirname(nextPath)).not.toBe(oldDirectory)
  })

  it.skipIf(process.platform === 'win32')(
    'keeps concurrent wraps distinct and removes their policies on reset',
    async () => {
      const directory = mkdtempSync(join(tmpdir(), 'asrt-landstrip-reset-'))
      try {
        await SandboxManager.initialize({
          network: { allowedDomains: [], deniedDomains: [] },
          filesystem: {
            disabled: true,
            denyRead: [],
            allowWrite: [directory],
            denyWrite: [],
          },
          enableWeakerNetworkIsolation: true,
        })
        const invocations = await Promise.all(
          Array.from({ length: 16 }, (_, index) =>
            SandboxManager.wrapWithSandboxArgv(
              `printf ${index}`,
              undefined,
              undefined,
              undefined,
              directory,
            ),
          ),
        )
        const policyPaths = invocations.map(({ argv }) => {
          const policyPath = argv.at(-1)?.match(/\s-p\s+(\S+)/u)?.[1]
          expect(policyPath).toBeDefined()
          return policyPath!
        })

        expect(new Set(policyPaths).size).toBe(policyPaths.length)
        policyPaths.forEach(path => expect(existsSync(path)).toBe(true))
        const resetPromise = SandboxManager.reset()
        // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects.toThrow() as void; the await is required at runtime
        await expect(
          SandboxManager.wrapWithSandboxArgv('printf too-late'),
        ).rejects.toThrow('initialize() must be called')
        await resetPromise
        policyPaths.forEach(path => expect(existsSync(path)).toBe(false))
      } finally {
        await SandboxManager.reset()
        rmSync(directory, { recursive: true, force: true })
      }
    },
  )

  it.skipIf(process.platform !== 'darwin')(
    'retains the legacy Seatbelt backend for unsupported macOS semantics',
    async () => {
      const directory = mkdtempSync(join(tmpdir(), 'asrt-landstrip-fallback-'))
      const variants = [
        { name: 'strict isolation' },
        {
          name: 'PTY access',
          enableWeakerNetworkIsolation: true,
          allowPty: true,
        },
        {
          name: 'filesystem policy',
          enableWeakerNetworkIsolation: true,
          filesystemDisabled: false,
        },
        {
          name: 'tagged monitoring',
          enableWeakerNetworkIsolation: true,
          enableLogMonitor: true,
        },
        {
          name: 'Mach lookup',
          enableWeakerNetworkIsolation: true,
          network: { allowMachLookup: ['com.example.service'] },
        },
        {
          name: 'Apple Events',
          enableWeakerNetworkIsolation: true,
          allowAppleEvents: true,
        },
      ]

      try {
        for (const variant of variants) {
          await SandboxManager.initialize(
            {
              network: {
                allowedDomains: [],
                deniedDomains: [],
                ...variant.network,
              },
              filesystem: {
                disabled: variant.filesystemDisabled ?? true,
                denyRead: [],
                allowWrite: [directory],
                denyWrite: [],
              },
              enableWeakerNetworkIsolation:
                variant.enableWeakerNetworkIsolation ?? false,
              allowPty: variant.allowPty,
              allowAppleEvents: variant.allowAppleEvents,
            },
            undefined,
            variant.enableLogMonitor,
          )
          const { argv } = await SandboxManager.wrapWithSandboxArgv(
            'true',
            undefined,
            undefined,
            undefined,
            directory,
          )
          const wrapped = argv.join(' ')
          expect(wrapped, variant.name).toContain('sandbox-exec')
          if (variant.name === 'strict isolation') {
            expect(wrapped).not.toContain('com.apple.trustd.agent')
          }
          await SandboxManager.reset()
        }
      } finally {
        await SandboxManager.reset()
        rmSync(directory, { recursive: true, force: true })
      }
    },
  )

  it.skipIf(process.platform === 'win32')(
    'does not trust child stderr as a Landstrip violation channel',
    async () => {
      const command = `landstrip-trap-${Date.now()}`
      const store = SandboxManager.getSandboxViolationStore()
      store.clear()

      try {
        await SandboxManager.initialize({
          network: {
            allowedDomains: [],
            deniedDomains: [],
            allowLocalBinding: true,
          },
          filesystem: {
            disabled: true,
            denyRead: [],
            allowWrite: [],
            denyWrite: [],
          },
          enableWeakerNetworkIsolation: true,
        })
        const { argv } = await SandboxManager.wrapWithSandboxArgv(command)
        expect(argv.join(' ')).toContain(binaryPath())
        const stderr = JSON.stringify({
          kind: 'filesystem',
          code: 'FILESYSTEM_DENIED',
          state: 'info',
          operation: 'read',
          path: '/private/secret',
          errno: 'EACCES',
          mechanism: 'seccomp',
        })

        expect(
          SandboxManager.annotateStderrWithSandboxFailures(command, stderr),
        ).toBe(stderr)
        expect(store.getViolationsForCommand(command)).toHaveLength(0)
      } finally {
        await SandboxManager.reset()
        store.clear()
      }
    },
  )

  it.skipIf(process.platform === 'win32')(
    'emits a policy accepted by the bundled native binary',
    () => {
      const directory = mkdtempSync(join(tmpdir(), 'asrt-landstrip-test-'))
      try {
        const shell = '/bin/sh'
        const invocation = wrapCommandWithLandstrip({
          landstripPath: binaryPath(),
          platform: process.platform === 'darwin' ? 'macos' : 'linux',
          cwd: directory,
          shell: { exe: shell, args: ['-c'] },
          command: 'true',
          needsNetworkRestriction: false,
          readConfig: { denyOnly: [], allowWithinDeny: [directory] },
          writeConfig: { allowOnly: [directory], denyWithinAllow: [] },
        })
        const result = spawnSync(
          binaryPath(),
          ['policy', 'validate', '-p', invocation.policyPath],
          { encoding: 'utf8', windowsHide: true },
        )

        expect(result.status, result.stderr).toBe(0)
        expect(
          JSON.parse(readFileSync(invocation.policyPath, 'utf8')),
        ).toBeTruthy()
      } finally {
        rmSync(directory, { recursive: true, force: true })
      }
    },
  )

  it.skipIf(process.platform !== 'linux')(
    'preserves and enforces recursive denyWrite globs through SandboxManager',
    async () => {
      const directory = mkdtempSync(join(tmpdir(), 'asrt-landstrip-run-'))
      const blockedPattern = join(directory, '**', 'secrets', '**')
      const blockedPath = join(directory, 'nested', 'secrets', 'value')
      try {
        await SandboxManager.initialize({
          network: { allowedDomains: [], deniedDomains: [] },
          filesystem: {
            denyRead: [],
            allowWrite: [directory],
            denyWrite: [blockedPattern],
          },
        })
        const invocation = await SandboxManager.wrapWithSandboxArgv(
          'mkdir -p nested/secrets; printf allowed > allowed; printf blocked > nested/secrets/value',
          undefined,
          undefined,
          undefined,
          directory,
        )
        const policyPath = invocation.argv.at(-1)?.match(/\s-p\s+(\S+)/u)?.[1]
        expect(policyPath).toBeDefined()
        const policy = JSON.parse(readFileSync(policyPath!, 'utf8')) as {
          filesystem: { denyWrite: string[] }
        }
        expect(policy.filesystem.denyWrite).toContain(blockedPattern)

        const result = spawnSync(
          invocation.argv[0]!,
          invocation.argv.slice(1),
          {
            cwd: directory,
            env: invocation.env,
            encoding: 'utf8',
            windowsHide: true,
          },
        )

        expect(result.status, result.stderr).not.toBe(0)
        expect(readFileSync(join(directory, 'allowed'), 'utf8')).toBe('allowed')
        expect(existsSync(join(directory, 'nested', 'secrets'))).toBe(true)
        expect(existsSync(blockedPath)).toBe(false)
      } finally {
        await SandboxManager.reset()
        rmSync(directory, { recursive: true, force: true })
      }
    },
  )
})
