<template>
  <div class="space-y-6 animate-fade-in max-w-2xl">
    <div class="page-header">
      <div>
        <h1 class="page-title">系统设置</h1>
        <p class="page-subtitle">账号安全、系统配置、数据备份</p>
      </div>
    </div>

    <!-- ─── Account Security ────────────────────────────────────────────── -->
    <section class="glass-card overflow-hidden">
      <div class="flex items-center gap-3 px-6 py-4 border-b border-slate-100 bg-slate-50/50">
        <div class="w-8 h-8 rounded-lg bg-vane-100 flex items-center justify-center">
          <User :size="15" class="text-vane-600" />
        </div>
        <div>
          <h3 class="font-semibold text-slate-800 text-sm">账号安全</h3>
          <p class="text-xs text-slate-400">修改登录用户名和密码</p>
        </div>
      </div>

      <div class="p-6 space-y-5">
        <div>
          <label class="input-label">用户名</label>
          <input v-model="form.username" class="input max-w-xs" autocomplete="username" />
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label class="input-label">新密码</label>
            <div class="relative">
              <input v-model="form.new_password"
                     :type="showPwd ? 'text' : 'password'"
                     class="input pr-10" placeholder="留空则不修改"
                     autocomplete="new-password" />
              <button type="button" @click="showPwd=!showPwd"
                      class="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600">
                <Eye v-if="!showPwd" :size="15" />
                <EyeOff v-else :size="15" />
              </button>
            </div>
          </div>
          <div>
            <label class="input-label">确认新密码</label>
            <input v-model="form.confirm_password"
                   :type="showPwd ? 'text' : 'password'"
                   class="input" placeholder="再次输入新密码"
                   autocomplete="new-password" />
          </div>
        </div>

        <div v-if="form.new_password" class="flex items-center gap-2">
          <div class="flex gap-1">
            <div v-for="i in 4" :key="i"
                 class="h-1.5 w-8 rounded-full transition-colors duration-300"
                 :class="pwdStrength >= i ? pwdStrengthColor : 'bg-slate-200'"></div>
          </div>
          <span class="text-xs" :class="pwdStrength >= 3 ? 'text-emerald-600' : 'text-amber-600'">
            {{ pwdStrengthLabel }}
          </span>
        </div>
      </div>
    </section>

    <!-- ─── System Config ───────────────────────────────────────────────── -->
    <section class="glass-card overflow-hidden">
      <div class="flex items-center gap-3 px-6 py-4 border-b border-slate-100 bg-slate-50/50">
        <div class="w-8 h-8 rounded-lg bg-slate-100 flex items-center justify-center">
          <Settings2 :size="15" class="text-slate-600" />
        </div>
        <div>
          <h3 class="font-semibold text-slate-800 text-sm">系统配置</h3>
          <p class="text-xs text-slate-400">管理端口和访问安全设置</p>
        </div>
      </div>

      <div class="p-6 space-y-5">
        <!-- Admin port -->
        <div>
          <label class="input-label">管理界面端口</label>
          <div class="flex items-center gap-3 max-w-xs">
            <input v-model.number="form.port" type="number" min="1" max="65535" class="input" />
          </div>
          <p class="text-xs text-slate-400 mt-1.5 flex items-center gap-1">
            <AlertTriangle :size="11" class="text-amber-400" />
            修改后需重启 Vane 进程才能生效
          </p>
        </div>

        <!-- Safe entry -->
        <div>
          <label class="input-label">安全访问路径（隐藏入口）</label>
          <div class="flex items-stretch gap-0 max-w-sm rounded-xl overflow-hidden border border-slate-200 focus-within:ring-2 focus-within:ring-vane-400 focus-within:border-transparent bg-slate-50">
            <span class="flex items-center px-3 text-xs text-slate-400 bg-slate-100 border-r border-slate-200 whitespace-nowrap select-none">
              :{{ form.port }}/
            </span>
            <input v-model="form.safe_entry"
                   class="flex-1 px-3 py-2.5 text-sm bg-transparent focus:outline-none font-mono"
                   placeholder="留空不启用" />
          </div>

          <div class="mt-2 space-y-1.5">
            <p class="text-xs text-slate-400">
              启用后仅能通过
              <code class="bg-slate-100 px-1.5 py-0.5 rounded text-slate-700 font-mono text-xs">
                :{{ form.port }}/{{ form.safe_entry || '路径' }}
              </code>
              访问管理界面
            </p>
            <div v-if="form.safe_entry" class="flex items-center gap-1.5 text-xs text-amber-600">
              <AlertTriangle :size="11" />
              请务必记住此路径，设置后直接访问根路径将返回 403
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- ─── Save feedback ───────────────────────────────────────────────── -->
    <div v-if="saved" class="flex items-center gap-2 text-emerald-700 bg-emerald-50 px-4 py-3 rounded-xl border border-emerald-200 text-sm">
      <CheckCircle :size="15" /> 设置已保存
    </div>
    <div v-if="saveError" class="flex items-center gap-2 text-red-600 bg-red-50 px-4 py-3 rounded-xl border border-red-200 text-sm">
      <AlertCircle :size="15" /> {{ saveError }}
    </div>

    <button class="btn-primary" @click="save" :disabled="saving">
      <Save :size="15" /> {{ saving ? '保存中...' : '保存设置' }}
    </button>

    <!-- ─── Backup & Restore ────────────────────────────────────────────── -->
    <section class="glass-card overflow-hidden">
      <div class="flex items-center gap-3 px-6 py-4 border-b border-slate-100 bg-slate-50/50">
        <div class="w-8 h-8 rounded-lg bg-emerald-50 flex items-center justify-center">
          <HardDrive :size="15" class="text-emerald-600" />
        </div>
        <div>
          <h3 class="font-semibold text-slate-800 text-sm">配置备份与恢复</h3>
          <p class="text-xs text-slate-400">导出加密备份文件，或从备份中恢复</p>
        </div>
      </div>

      <div class="p-6 space-y-4">
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <!-- Backup card -->
          <div class="p-4 bg-slate-50 rounded-xl border border-slate-200 space-y-3">
            <div class="flex items-center gap-2">
              <Download :size="15" class="text-slate-500" />
              <span class="text-sm font-medium text-slate-700">备份配置</span>
            </div>
            <p class="text-xs text-slate-400">导出所有规则和证书配置，备份文件经 AES-256 加密</p>
            <button class="btn-secondary btn-sm w-full justify-center" @click="backup">
              <Download :size="13" /> 下载备份文件
            </button>
          </div>

          <!-- Restore card -->
          <div class="p-4 bg-slate-50 rounded-xl border border-slate-200 space-y-3">
            <div class="flex items-center gap-2">
              <Upload :size="15" class="text-slate-500" />
              <span class="text-sm font-medium text-slate-700">恢复配置</span>
            </div>
            <p class="text-xs text-slate-400">从 .enc 备份文件恢复，恢复后所有服务自动重启</p>
            <label class="btn btn-secondary btn-sm w-full justify-center cursor-pointer">
              <Upload :size="13" /> 选择备份文件
              <input type="file" accept=".enc,.json" class="hidden" @change="restore" />
            </label>
          </div>
        </div>

        <div v-if="restoreMsg" class="flex items-center gap-2 text-emerald-700 bg-emerald-50 px-4 py-3 rounded-xl border border-emerald-200 text-sm">
          <CheckCircle :size="14" /> {{ restoreMsg }}
        </div>
        <div v-if="restoreError" class="flex items-center gap-2 text-red-600 bg-red-50 px-4 py-3 rounded-xl border border-red-200 text-sm">
          <AlertCircle :size="14" /> {{ restoreError }}
        </div>
      </div>
    </section>

    <!-- ─── About ────────────────────────────────────────────────────────── -->
    <section class="glass-card overflow-hidden">
      <div class="flex items-center gap-3 px-6 py-4 border-b border-slate-100 bg-slate-50/50">
        <div class="w-8 h-8 rounded-lg bg-purple-50 flex items-center justify-center">
          <Info :size="15" class="text-purple-500" />
        </div>
        <div>
          <h3 class="font-semibold text-slate-800 text-sm">关于 Vane</h3>
          <p class="text-xs text-slate-400">版本信息与数据存储说明</p>
        </div>
      </div>
      <div class="p-6">
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
          <div class="space-y-3">
            <div class="flex justify-between">
              <span class="text-slate-500">数据加密</span>
              <span class="font-mono text-xs text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded">AES-256-GCM</span>
            </div>
            <div class="flex justify-between">
              <span class="text-slate-500">密码哈希</span>
              <span class="font-mono text-xs text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded">bcrypt</span>
            </div>
            <div class="flex justify-between">
              <span class="text-slate-500">证书申请</span>
              <span class="text-slate-700">ACME DNS-01</span>
            </div>
          </div>
          <div class="space-y-3">
            <div class="flex justify-between">
              <span class="text-slate-500">数据目录</span>
              <span class="font-mono text-xs text-slate-600 bg-slate-100 px-2 py-0.5 rounded">./data/</span>
            </div>
            <div class="flex justify-between">
              <span class="text-slate-500">配置文件</span>
              <span class="font-mono text-xs text-slate-600 bg-slate-100 px-2 py-0.5 rounded">config.enc</span>
            </div>
            <div class="flex justify-between">
              <span class="text-slate-500">备份目录</span>
              <span class="font-mono text-xs text-slate-600 bg-slate-100 px-2 py-0.5 rounded">./data/backups/</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import {
  User, Settings2, Save, CheckCircle, AlertCircle,
  HardDrive, Download, Upload, AlertTriangle,
  Eye, EyeOff, Info
} from 'lucide-vue-next'
import { api } from '@/stores/auth'

const form = ref({ username: '', new_password: '', confirm_password: '', port: 4455, safe_entry: '' })
const saved    = ref(false)
const saveError = ref('')
const saving   = ref(false)
const showPwd  = ref(false)
const restoreMsg   = ref('')
const restoreError = ref('')

// Password strength
const pwdStrength = computed(() => {
  const p = form.value.new_password
  if (!p) return 0
  let s = 0
  if (p.length >= 8)  s++
  if (p.length >= 12) s++
  if (/[A-Z]/.test(p) && /[a-z]/.test(p)) s++
  if (/[0-9]/.test(p) && /[^A-Za-z0-9]/.test(p)) s++
  return Math.min(4, s)
})
const pwdStrengthColor = computed(() => {
  const colors = ['bg-red-400', 'bg-orange-400', 'bg-amber-400', 'bg-emerald-500']
  return colors[pwdStrength.value - 1] || 'bg-slate-200'
})
const pwdStrengthLabel = computed(() => {
  return ['', '弱', '一般', '较强', '强'][pwdStrength.value] || ''
})

async function load() {
  const { data } = await api.get('/settings')
  form.value.username  = data.username
  form.value.port      = data.port
  form.value.safe_entry = data.safe_entry || ''
}

async function save() {
  saveError.value = ''
  if (form.value.new_password && form.value.new_password !== form.value.confirm_password) {
    saveError.value = '两次输入的密码不一致'
    return
  }
  if (form.value.new_password && form.value.new_password.length < 6) {
    saveError.value = '密码长度不能少于 6 位'
    return
  }
  saving.value = true
  try {
    await api.put('/settings', {
      username:     form.value.username,
      new_password: form.value.new_password || '',
      port:         form.value.port,
      safe_entry:   form.value.safe_entry,
    })
    form.value.new_password = ''
    form.value.confirm_password = ''
    saved.value = true
    setTimeout(() => saved.value = false, 3000)
  } catch (e) {
    saveError.value = e.response?.data?.error || e.message
  } finally {
    saving.value = false
  }
}

async function backup() {
  const resp = await api.get('/settings/backup', { responseType: 'blob' })
  const url = URL.createObjectURL(resp.data)
  const a = document.createElement('a')
  a.href = url
  a.download = `vane-backup-${new Date().toISOString().slice(0,10)}.enc`
  a.click()
  URL.revokeObjectURL(url)
}

async function restore(e) {
  restoreMsg.value = ''
  restoreError.value = ''
  const file = e.target.files[0]
  if (!file) return
  try {
    const buf = await file.arrayBuffer()
    const bytes = new Uint8Array(buf)
    await api.post('/settings/restore', bytes, {
      headers: { 'Content-Type': 'application/octet-stream' }
    })
    restoreMsg.value = '配置已恢复，服务已重启'
  } catch (err) {
    restoreError.value = '恢复失败：' + (err.response?.data?.error || err.message)
  }
  e.target.value = ''
}

onMounted(load)
</script>
