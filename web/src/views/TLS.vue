<template>
  <div class="space-y-6 animate-fade-in">
    <div class="page-header">
      <div>
        <h1 class="page-title">TLS 证书</h1>
        <p class="page-subtitle">DNS-01 自动申请证书，支持 Let's Encrypt 和 ZeroSSL，手动上传，自动续期</p>
      </div>
      <div class="flex gap-2">
        <button class="btn-secondary" @click="openUpload()">
          <Upload :size="16" /> 上传证书
        </button>
        <button class="btn-primary" @click="openModal()">
          <Plus :size="16" /> 申请证书
        </button>
      </div>
    </div>

    <div v-if="certs.length === 0" class="glass-card p-16 text-center">
      <div class="w-16 h-16 rounded-3xl bg-amber-50 flex items-center justify-center mx-auto mb-4">
        <Shield :size="28" class="text-amber-400" />
      </div>
      <p class="text-slate-500 font-medium">暂无 TLS 证书</p>
      <p class="text-slate-400 text-sm mt-1">点击右上角申请或上传证书</p>
    </div>

    <div v-else class="grid gap-4">
      <div v-for="cert in certs" :key="cert.id"
           class="glass-card p-5 group hover:shadow-colored-amber transition-all duration-300">
        <div class="flex items-center gap-4">
          <!-- Days badge -->
          <div class="w-14 h-14 rounded-2xl flex flex-col items-center justify-center flex-shrink-0 text-white"
               :style="`background: ${certGradient(cert.days_left)}`">
            <Lock :size="16" class="mb-0.5" />
            <span class="text-xs font-bold leading-none">{{ cert.days_left >= 0 ? cert.days_left : '?' }}</span>
            <span class="text-[9px] opacity-80">DAYS</span>
          </div>

          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2 mb-1.5 flex-wrap">
              <span class="font-semibold text-slate-900 font-mono">{{ cert.domain }}</span>
              <StatusBadge :status="cert.status" />
              <span class="badge badge-slate text-xs">{{ cert.source === 'acme' ? 'ACME' : '手动' }}</span>
              <!-- CA badge -->
              <span v-if="cert.ca_provider === 'zerossl'" class="badge text-xs" style="background:#f0f9ff;color:#0369a1;border:1px solid #bae6fd">ZeroSSL</span>
              <span v-else-if="cert.source === 'acme'" class="badge text-xs" style="background:#f0fdf4;color:#166534;border:1px solid #bbf7d0">Let's Encrypt</span>
              <ProviderBadge v-if="cert.provider" :provider="cert.provider" />
              <span v-if="cert.auto_renew" class="badge badge-green text-xs">自动续期</span>
            </div>

            <div class="h-1.5 bg-slate-100 rounded-full overflow-hidden mb-2 max-w-xs">
              <div class="h-full rounded-full transition-all duration-700"
                   :style="`width: ${Math.min(100, Math.max(0, cert.days_left/90*100))}%; background: ${certBarColor(cert.days_left)}`"></div>
            </div>

            <div class="flex items-center gap-4 text-xs text-slate-400">
              <span v-if="cert.issued_at">签发: {{ fmtDate(cert.issued_at) }}</span>
              <span v-if="cert.expires_at">到期: {{ fmtDate(cert.expires_at) }}</span>
            </div>
          </div>

          <div class="flex items-center gap-1.5 flex-shrink-0">
            <!-- Download (only if cert exists) -->
            <button v-if="cert.status === 'active'" @click="downloadCert(cert)"
                    class="btn-ghost btn-sm text-slate-500" title="下载证书">
              <Download :size="13" />
            </button>
            <!-- View PEM -->
            <button v-if="cert.status === 'active'" @click="viewPEM(cert)"
                    class="btn-ghost btn-sm text-slate-500" title="查看证书内容">
              <Eye :size="13" />
            </button>
            <!-- Edit -->
            <button @click="openEdit(cert)" class="btn-ghost btn-sm text-slate-500" title="编辑">
              <Pencil :size="13" />
            </button>
            <!-- Re-issue (ACME only) -->
            <button v-if="cert.source === 'acme'" @click="issue(cert.id)"
                    class="btn-secondary btn-sm" :disabled="cert.status === 'pending'">
              <RefreshCw :size="13" :class="cert.status === 'pending' ? 'animate-spin' : ''" />
              {{ cert.status === 'pending' ? '申请中' : '重新申请' }}
            </button>
            <button @click="del(cert.id)" class="btn-ghost btn-sm text-red-400 hover:text-red-500 hover:bg-red-50">
              <Trash2 :size="13" />
            </button>
          </div>
        </div>

        <!-- Error message -->
        <div v-if="cert.status === 'error'" class="mt-3 px-3 py-2 bg-red-50 rounded-lg border border-red-100 text-xs text-red-600 flex items-center gap-2">
          <AlertCircle :size="13" />
          申请失败，请检查 DNS 提供商配置后重新申请
        </div>
      </div>
    </div>

    <!-- ─── Apply / Edit cert modal ─────────────────────────────────────── -->
    <Teleport to="body">
      <div v-if="modal" class="modal-overlay" @click.self="modal=null">
        <div class="modal-box max-w-lg">
          <div class="flex items-center justify-between p-6 border-b border-slate-100">
            <div>
              <h3 class="font-semibold text-slate-900">{{ editId ? '编辑证书' : '申请 ACME 证书' }}</h3>
              <p class="text-xs text-slate-400 mt-0.5">DNS-01 验证，支持泛域名，无需开放 80/443 端口</p>
            </div>
            <button @click="modal=null" class="btn-ghost btn-sm"><X :size="16" /></button>
          </div>

          <div class="p-6 space-y-4 max-h-[70vh] overflow-y-auto">
            <!-- CA Provider -->
            <div>
              <label class="input-label">证书颁发机构 (CA)</label>
              <div class="grid grid-cols-2 gap-3">
                <button type="button"
                  @click="form.ca_provider='letsencrypt'"
                  :class="['ca-btn', form.ca_provider !== 'zerossl' ? 'ca-btn-active' : '']">
                  <div class="font-semibold text-sm">Let's Encrypt</div>
                  <div class="text-xs text-slate-400 mt-0.5">免费，每3个月续期，全球信任</div>
                </button>
                <button type="button"
                  @click="form.ca_provider='zerossl'"
                  :class="['ca-btn', form.ca_provider === 'zerossl' ? 'ca-btn-active' : '']">
                  <div class="font-semibold text-sm">ZeroSSL</div>
                  <div class="text-xs text-slate-400 mt-0.5">免费，需要邮箱注册 EAB 凭据</div>
                </button>
              </div>
            </div>

            <div>
              <label class="input-label">域名</label>
              <input v-model="form.domain" class="input font-mono" placeholder="example.com 或 *.example.com" />
            </div>

            <div>
              <label class="input-label">邮箱（ACME 账号）</label>
              <input v-model="form.email" class="input" type="email" placeholder="admin@example.com" />
            </div>

            <!-- ZeroSSL EAB -->
            <div v-if="form.ca_provider === 'zerossl'"
                 class="p-4 bg-sky-50 rounded-xl border border-sky-100 space-y-3">
              <div class="flex items-start gap-2">
                <Info :size="14" class="text-sky-500 mt-0.5 flex-shrink-0" />
                <p class="text-xs text-sky-700">
                  ZeroSSL 需要 EAB（外部账号绑定）凭据。
                  前往 <a href="https://app.zerossl.com/developer" target="_blank" class="underline font-medium">ZeroSSL 开发者页面</a> 生成 EAB Key ID 和 HMAC Key。
                </p>
              </div>
              <div>
                <label class="input-label">EAB Key ID</label>
                <input v-model="form.provider_conf.zerossl_key_id" class="input font-mono text-xs" placeholder="ZeroSSL EAB Key ID" />
              </div>
              <div>
                <label class="input-label">EAB HMAC Key</label>
                <input v-model="form.provider_conf.zerossl_api_key" class="input font-mono text-xs" placeholder="ZeroSSL EAB HMAC Key" />
              </div>
            </div>

            <!-- DNS Provider -->
            <div>
              <label class="input-label">DNS 服务商</label>
              <select v-model="form.provider" class="select">
                <option value="cloudflare">Cloudflare</option>
              </select>
            </div>

            <template v-if="form.provider === 'cloudflare'">
              <div class="p-4 bg-amber-50 rounded-xl border border-amber-100 space-y-3">
                <h4 class="text-xs font-bold text-amber-700 uppercase tracking-wide">Cloudflare DNS API</h4>
                <div class="p-3 bg-amber-100/60 rounded-lg text-xs text-amber-700">
                  需要创建一个具有 <strong>DNS:Edit</strong> 权限的 API Token（不是 Global API Key）
                </div>
                <div>
                  <label class="input-label">API Token</label>
                  <input v-model="form.provider_conf.api_token" class="input font-mono text-xs" placeholder="CF API Token (DNS:Edit)" />
                </div>
                <div>
                  <label class="input-label">Zone ID</label>
                  <input v-model="form.provider_conf.zone_id" class="input font-mono text-xs" placeholder="域名 Zone ID（可选，自动检测）" />
                </div>
              </div>
            </template>

            <div class="flex items-center gap-3">
              <label class="toggle">
                <input type="checkbox" v-model="form.auto_renew" />
                <div class="toggle-track"></div>
                <div class="toggle-thumb"></div>
              </label>
              <span class="text-sm text-slate-600">到期前 30 天自动续期</span>
            </div>

            <div v-if="modalError" class="flex items-center gap-2 text-red-600 bg-red-50 px-3 py-2.5 rounded-xl border border-red-100 text-xs">
              <AlertCircle :size="13" /> {{ modalError }}
            </div>
          </div>

          <div class="flex justify-end gap-3 px-6 pb-6">
            <button class="btn-secondary" @click="modal=null">取消</button>
            <button class="btn-primary" @click="editId ? updateCert() : createAndIssue()" :disabled="saving">
              <Shield :size="14" />
              {{ editId ? '保存并重新申请' : '创建并申请' }}
            </button>
          </div>
        </div>
      </div>
    </Teleport>

    <!-- ─── Upload modal ─────────────────────────────────────────────────── -->
    <Teleport to="body">
      <div v-if="uploadModal" class="modal-overlay" @click.self="uploadModal=null">
        <div class="modal-box">
          <div class="flex items-center justify-between p-6 border-b border-slate-100">
            <h3 class="font-semibold text-slate-900">上传证书</h3>
            <button @click="uploadModal=null" class="btn-ghost btn-sm"><X :size="16" /></button>
          </div>
          <div class="p-6 space-y-4">
            <div>
              <label class="input-label">域名</label>
              <input v-model="uploadForm.domain" class="input font-mono" placeholder="example.com" />
            </div>
            <div>
              <label class="input-label">证书内容 (PEM)</label>
              <textarea v-model="uploadForm.cert_pem" class="input font-mono text-xs h-28 resize-none"
                        placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"></textarea>
            </div>
            <div>
              <label class="input-label">私钥内容 (PEM)</label>
              <textarea v-model="uploadForm.key_pem" class="input font-mono text-xs h-28 resize-none"
                        placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"></textarea>
            </div>
            <div class="flex items-center gap-3">
              <label class="toggle">
                <input type="checkbox" v-model="uploadForm.auto_renew" />
                <div class="toggle-track"></div>
                <div class="toggle-thumb"></div>
              </label>
              <span class="text-sm text-slate-600">自动续期（需要有 ACME 配置）</span>
            </div>
          </div>
          <div class="flex justify-end gap-3 px-6 pb-6">
            <button class="btn-secondary" @click="uploadModal=null">取消</button>
            <button class="btn-primary" @click="upload"><Upload :size="14" /> 上传</button>
          </div>
        </div>
      </div>
    </Teleport>

    <!-- ─── View PEM modal ───────────────────────────────────────────────── -->
    <Teleport to="body">
      <div v-if="pemModal" class="modal-overlay" @click.self="pemModal=null">
        <div class="modal-box max-w-2xl">
          <div class="flex items-center justify-between p-6 border-b border-slate-100">
            <div>
              <h3 class="font-semibold text-slate-900 font-mono">{{ pemData.domain }}</h3>
              <p class="text-xs text-slate-400 mt-0.5">证书内容</p>
            </div>
            <div class="flex gap-2">
              <button class="btn-secondary btn-sm" @click="downloadFromPEM()"><Download :size="13" /> 下载证书</button>
              <button class="btn-secondary btn-sm" @click="downloadKeyFromPEM()"><Download :size="13" /> 下载私钥</button>
              <button @click="pemModal=null" class="btn-ghost btn-sm"><X :size="16" /></button>
            </div>
          </div>
          <div class="p-6 space-y-4">
            <div>
              <div class="flex items-center justify-between mb-1.5">
                <label class="input-label mb-0">证书 (cert.pem)</label>
                <button class="text-xs text-vane-500 hover:text-vane-700" @click="copy(pemData.cert_pem)">
                  <Copy :size="12" class="inline mr-1" />复制
                </button>
              </div>
              <textarea readonly class="input font-mono text-xs h-40 resize-none bg-slate-50" :value="pemData.cert_pem"></textarea>
            </div>
            <div>
              <div class="flex items-center justify-between mb-1.5">
                <label class="input-label mb-0">私钥 (key.pem)</label>
                <button class="text-xs text-vane-500 hover:text-vane-700" @click="copy(pemData.key_pem)">
                  <Copy :size="12" class="inline mr-1" />复制
                </button>
              </div>
              <textarea readonly class="input font-mono text-xs h-40 resize-none bg-slate-50" :value="pemData.key_pem"></textarea>
            </div>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import {
  Plus, Shield, Lock, RefreshCw, Upload, Trash2, X,
  Download, Eye, Pencil, AlertCircle, Info, Copy
} from 'lucide-vue-next'
import { api } from '@/stores/auth'
import ProviderBadge from '@/components/ProviderBadge.vue'
import StatusBadge from '@/components/StatusBadge.vue'

const certs = ref([])
const modal = ref(null)
const uploadModal = ref(null)
const pemModal = ref(false)
const pemData = ref({})
const form = ref({})
const uploadForm = ref({})
const editId = ref(null)
const saving = ref(false)
const modalError = ref('')

function fmtDate(s) {
  if (!s) return ''
  return new Date(s).toLocaleDateString('zh-CN')
}
function certGradient(days) {
  if (days < 0)  return 'linear-gradient(135deg,#94a3b8,#64748b)'
  if (days < 14) return 'linear-gradient(135deg,#ef4444,#dc2626)'
  if (days < 30) return 'linear-gradient(135deg,#f59e0b,#d97706)'
  return 'linear-gradient(135deg,#10b981,#059669)'
}
function certBarColor(days) {
  if (days < 14) return '#ef4444'
  if (days < 30) return '#f59e0b'
  return '#10b981'
}

async function load() {
  const { data } = await api.get('/tls')
  certs.value = data
}

function blankForm() {
  return {
    domain: '', email: '', ca_provider: 'letsencrypt',
    provider: 'cloudflare', provider_conf: {}, auto_renew: true, source: 'acme'
  }
}

function openModal() {
  editId.value = null
  modalError.value = ''
  form.value = blankForm()
  modal.value = true
}

function openEdit(cert) {
  editId.value = cert.id
  modalError.value = ''
  form.value = {
    domain:        cert.domain,
    email:         cert.email || '',
    ca_provider:   cert.ca_provider || 'letsencrypt',
    provider:      cert.provider || 'cloudflare',
    provider_conf: cert.provider_conf || {},
    auto_renew:    cert.auto_renew,
    source:        cert.source,
  }
  modal.value = true
}

function openUpload() {
  uploadForm.value = { domain: '', cert_pem: '', key_pem: '', auto_renew: false }
  uploadModal.value = true
}

function validateForm() {
  if (!form.value.domain) return '请输入域名'
  if (!form.value.email)  return '请输入邮箱'
  if (form.value.ca_provider === 'zerossl') {
    if (!form.value.provider_conf.zerossl_key_id) return '请输入 ZeroSSL EAB Key ID'
    if (!form.value.provider_conf.zerossl_api_key) return '请输入 ZeroSSL EAB HMAC Key'
  }
  if (form.value.provider === 'cloudflare' && !form.value.provider_conf.api_token) {
    return '请输入 Cloudflare API Token'
  }
  return null
}

async function createAndIssue() {
  modalError.value = validateForm() || ''
  if (modalError.value) return
  saving.value = true
  try {
    const { data } = await api.post('/tls', { ...form.value })
    modal.value = null
    await api.post(`/tls/${data.id}/issue`)
    await load()
  } catch(e) {
    modalError.value = e.response?.data?.error || e.message
  } finally {
    saving.value = false
  }
}

async function updateCert() {
  modalError.value = validateForm() || ''
  if (modalError.value) return
  saving.value = true
  try {
    await api.put(`/tls/${editId.value}`, { ...form.value })
    modal.value = null
    // If ACME cert, re-issue after update
    if (form.value.source === 'acme') {
      await api.post(`/tls/${editId.value}/issue`)
    }
    await load()
  } catch(e) {
    modalError.value = e.response?.data?.error || e.message
  } finally {
    saving.value = false
  }
}

async function issue(id) {
  await api.post(`/tls/${id}/issue`)
  await load()
}

async function upload() {
  await api.post('/tls/upload', uploadForm.value)
  uploadModal.value = null
  await load()
}

async function del(id) {
  if (!confirm('确认删除此证书？')) return
  await api.delete(`/tls/${id}`)
  await load()
}

// Download cert.pem directly
async function downloadCert(cert) {
  const { data } = await api.get(`/tls/${cert.id}/pem`)
  triggerDownload(cert.domain + '-cert.pem', data.cert_pem)
}

async function viewPEM(cert) {
  const { data } = await api.get(`/tls/${cert.id}/pem`)
  pemData.value = data
  pemModal.value = true
}

function downloadFromPEM() {
  triggerDownload(pemData.value.domain + '-cert.pem', pemData.value.cert_pem)
}
function downloadKeyFromPEM() {
  triggerDownload(pemData.value.domain + '-key.pem', pemData.value.key_pem)
}

function triggerDownload(filename, text) {
  const blob = new Blob([text], { type: 'application/x-pem-file' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = filename; a.click()
  URL.revokeObjectURL(url)
}

function copy(text) {
  navigator.clipboard.writeText(text).catch(() => {})
}

onMounted(load)
</script>

<style scoped>
.ca-btn {
  @apply p-3 rounded-xl border-2 border-slate-200 bg-white text-left cursor-pointer transition-all duration-200 hover:border-vane-300;
}
.ca-btn-active {
  @apply border-vane-500 bg-vane-50;
}
</style>
