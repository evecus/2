import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

const messages = {
  zh: {
    // Layout
    main: '主导航', system: '系统',
    dashboard: '仪表盘', portforward: '端口转发',
    ddns: '动态域名', webservice: 'Web 服务',
    tls: 'SSL 证书', settings: '设置',
    administrator: '管理员', running: '运行中',
    // Login
    welcomeBack: '欢迎回来', username: '用户名',
    password: '密码', signIn: '登录', signingIn: '登录中...',
    defaultHint: '默认：admin / admin',
    loginFailed: '登录失败',
    // Dashboard
    dashboardDesc: '所有服务概览',
    portTraffic: '端口转发流量', trafficDesc: '实时入站 / 出站',
    certExpiry: '证书有效期', certExpiryDesc: '到期剩余天数',
    noCerts: '暂无证书',
    quickStatus: '快速状态',
    portForwardRules: '条规则', webServices: '个服务',
    certCount: '张证书', certSoonExpire: '即将到期',
    sysInfo: '系统信息', version: '版本',
    uptime: '运行时间', adminPort: '管理端口',
    inbound: '入站', outbound: '出站',
    // Settings
    systemSettings: '系统设置',
    systemSettingsDesc: '账号安全、系统配置、数据备份',
    accountSecurity: '账号安全',
    accountSecurityDesc: '修改登录用户名和密码',
    newPassword: '新密码', confirmPassword: '确认新密码',
    passwordPlaceholder: '留空则不修改', confirmPlaceholder: '再次输入新密码',
    sysConfig: '系统配置', sysConfigDesc: '管理端口和访问安全设置',
    adminPortLabel: '管理界面端口', portRestartHint: '修改后需重启 Vane 进程才能生效',
    safeEntry: '安全访问路径（隐藏入口）',
    safeEntryPlaceholder: '留空不启用',
    safeEntryHint1: '启用后仅能通过',
    safeEntryHint2: '访问管理界面',
    safeEntryWarn: '请务必记住此路径，设置后直接访问根路径将返回 403',
    saveSettings: '保存设置', saving: '保存中...',
    settingsSaved: '设置已保存',
    pwdMismatch: '两次输入的密码不一致',
    pwdTooShort: '密码长度不能少于 6 位',
    backupRestore: '配置备份与恢复',
    backupRestoreDesc: '导出加密备份文件，或从备份中恢复',
    backupTitle: '备份配置', backupDesc: '导出所有规则和证书配置，备份文件经 AES-256 加密',
    downloadBackup: '下载备份文件',
    restoreTitle: '恢复配置', restoreDesc: '从 .enc 备份文件恢复，恢复后所有服务自动重启',
    selectBackup: '选择备份文件',
    restoreSuccess: '配置已恢复，服务已重启',
    restoreFailed: '恢复失败：',
    aboutVane: '关于 Vane', aboutDesc: '版本信息与数据存储说明',
    encryption: '数据加密', passwordHash: '密码哈希',
    certIssuance: '证书申请', dataDir: '数据目录',
    configFile: '配置文件', backupDir: '备份目录',
    language: '语言', switchLang: 'English',
    weak: '弱', fair: '一般', good: '较强', strong: '强',
    // WebService
    portOccupied: '端口 {port} 已被占用，请更换端口',
  },
  en: {
    main: 'MAIN', system: 'SYSTEM',
    dashboard: 'Dashboard', portforward: 'Port Forward',
    ddns: 'Dynamic Domain', webservice: 'Web Service',
    tls: 'SSL Certs', settings: 'Settings',
    administrator: 'Administrator', running: 'Running',
    welcomeBack: 'Welcome back', username: 'Username',
    password: 'Password', signIn: 'Sign In', signingIn: 'Signing in...',
    defaultHint: 'Default: admin / admin',
    loginFailed: 'Login failed',
    dashboardDesc: 'Overview of all services',
    portTraffic: 'Port Forward Traffic', trafficDesc: 'Live inbound / outbound',
    certExpiry: 'Certificate Expiry', certExpiryDesc: 'Days remaining',
    noCerts: 'No certificates',
    quickStatus: 'Quick Status',
    portForwardRules: 'rules', webServices: 'services',
    certCount: 'certs', certSoonExpire: 'expiring soon',
    sysInfo: 'System Info', version: 'Version',
    uptime: 'Uptime', adminPort: 'Admin Port',
    inbound: 'In', outbound: 'Out',
    systemSettings: 'System Settings',
    systemSettingsDesc: 'Account, system config, data backup',
    accountSecurity: 'Account Security',
    accountSecurityDesc: 'Change login username and password',
    newPassword: 'New Password', confirmPassword: 'Confirm Password',
    passwordPlaceholder: 'Leave blank to keep current', confirmPlaceholder: 'Re-enter new password',
    sysConfig: 'System Config', sysConfigDesc: 'Admin port and access security',
    adminPortLabel: 'Admin Panel Port', portRestartHint: 'Requires Vane restart to take effect',
    safeEntry: 'Safe Access Path (Hidden Entry)',
    safeEntryPlaceholder: 'Leave blank to disable',
    safeEntryHint1: 'When set, only accessible at',
    safeEntryHint2: '',
    safeEntryWarn: 'Remember this path — direct root access will return 403',
    saveSettings: 'Save Settings', saving: 'Saving...',
    settingsSaved: 'Settings saved',
    pwdMismatch: 'Passwords do not match',
    pwdTooShort: 'Password must be at least 6 characters',
    backupRestore: 'Backup & Restore',
    backupRestoreDesc: 'Export encrypted backup or restore from file',
    backupTitle: 'Backup Config', backupDesc: 'Export all rules and config. Backup is AES-256 encrypted.',
    downloadBackup: 'Download Backup',
    restoreTitle: 'Restore Config', restoreDesc: 'Restore from .enc backup. All services restart automatically.',
    selectBackup: 'Select Backup File',
    restoreSuccess: 'Config restored, services restarted',
    restoreFailed: 'Restore failed: ',
    aboutVane: 'About Vane', aboutDesc: 'Version info and data storage',
    encryption: 'Encryption', passwordHash: 'Password Hash',
    certIssuance: 'Cert Issuance', dataDir: 'Data Dir',
    configFile: 'Config File', backupDir: 'Backup Dir',
    language: 'Language', switchLang: '中文',
    weak: 'Weak', fair: 'Fair', good: 'Good', strong: 'Strong',
    portOccupied: 'Port {port} is already in use, please choose another',
  }
}

export const useI18n = defineStore('i18n', () => {
  const locale = ref(localStorage.getItem('vane_lang') || 'zh')

  function t(key, vars = {}) {
    let str = messages[locale.value]?.[key] ?? messages.zh[key] ?? key
    Object.entries(vars).forEach(([k, v]) => { str = str.replace(`{${k}}`, v) })
    return str
  }

  function toggle() {
    locale.value = locale.value === 'zh' ? 'en' : 'zh'
    localStorage.setItem('vane_lang', locale.value)
  }

  return { locale, t, toggle }
})
