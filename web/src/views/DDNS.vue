<template>
  <div class="space-y-6 animate-fade-in">
    <div class="page-header">
      <div>
        <h1 class="page-title">动态域名 DDNS</h1>
        <p class="page-subtitle">自动同步公网 IP 到 DNS 服务商，支持 Cloudflare、阿里云、DNSPod</p>
      </div>
      <button class="btn-primary" @click="openModal()">
        <Plus :size="16" /> 添加规则
      </button>
    </div>

    <div v-if="rules.length === 0" class="glass-card p-16 text-center">
      <div class="w-16 h-16 rounded-3xl bg-emerald-50 flex items-center justify-center mx-auto mb-4">
        <Globe :size="28" class="text-emerald-400" />
      </div>
      <p class="text-slate-500 font-medium">暂无 DDNS 规则</p>
    </div>

    <div v-else class="grid gap-4">
      <div v-for="rule in rules" :key="rule.id"
           class="glass-card p-5 group hover:shadow-colored-green transition-all duration-300">
        <div class="flex items-start gap-4">
          <div class="w-12 h-12 rounded-2xl flex items-center justify-center flex-shrink-0"
               :style="rule.enabled ? 'background:linear-gradient(135deg,#10b981,#059669)' : 'background:#f1f5f9'">
            <Globe :size="20" :class="rule.enabled ? 'text-white' : 'text-slate-400'" />
          </div>

          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2 mb-2 flex-wrap">
              <span class="font-semibold text-slate-900">{{ rule.name || '未命名' }}</span>
              <span class="status-dot" :class="rule.enabled ? 'active' : 'inactive'"></span>
              <ProviderBadge :provider="rule.provider" />
              <span class="badge badge-slate">{{ rule.ip_version === 'ipv6' ? 'IPv6' : 'IPv4' }}</span>
              <span v-if="rule.ip_detect_mode === 'iface'" class="badge text-xs" style="background:#f0f9ff;color:#0369a1;border:1px solid #bae6fd">
                网卡: {{ rule.ip_interface }}
              </span>
              <span v-else class="badge text-xs" style="background:#f0fdf4;color:#166534;border:1px solid #bbf7d0">外部 API</span>
            </div>

            <!-- Domain list -->
            <div class="flex flex-wrap gap-1.5 mb-3">
              <span v-for="d in effectiveDomains(rule)" :key="d"
                    class="font-mono text-xs text-slate-600 bg-slate-100 px-2 py-0.5 rounded-lg">{{ d }}</span>
            </div>

            <div class="flex items-end gap-0.5 h-6 mb-2">
              <div v-for="(rec, i) in (rule.ip_history||[]).slice(-30)" :key="i"
                   class="flex-1 rounded-sm"
                   :style="`height:${Math.max(3,(i+1)/30*24)}px;background:${rule.enabled?'#10b981':'#94a3b8'};opacity:${0.3+(i/30)*0.7}`"
                   :title="`${rec.ip} @ ${new Date(rec.timestamp).toLocaleString('zh-CN')}`"></div>
              <div v-if="!(rule.ip_history?.length)" class="text-xs text-slate-300 italic">暂无记录</div>
            </div>

            <div class="flex items-center gap-4 text-xs text-slate-400">
              <span>当前 IP: <span class="font-mono text-slate-600">{{ rule.last_ip || '未知' }}</span></span>
              <span v-if="rule.last_updated">更新: {{ new Date(rule.last_updated).toLocaleString('zh-CN') }}</span>
              <span>间隔: {{ rule.interval || 300 }}s</span>
            </div>
          </div>

          <div class="flex items-center gap-2 flex-shrink-0">
            <button @click="refresh(rule.id)" class="btn-ghost btn-sm text-emerald-500" title="立即检测">
              <RefreshCw :size="14" />
            </button>
            <label class="toggle">
              <input type="checkbox" :checked="rule.enabled" @change="toggle(rule.id)" />
              <div class="toggle-track"></div><div class="toggle-thumb"></div>
            </label>
            <button @click="openModal(rule)" class="btn-ghost btn-sm opacity-0 group-hover:opacity-100"><Pencil :size="14" /></button>
            <button @click="del(rule.id)" class="btn-ghost btn-sm text-red-400 hover:bg-red-50 opacity-0 group-hover:opacity-100"><Trash2 :size="14" /></button>
          </div>
        </div>
      </div>
    </div>

    <!-- Modal -->
    <Teleport to="body">
      <div v-if="modal" class="modal-overlay" @click.self="modal=null">
        <div class="modal-box max-w-lg">
          <div class="flex items-center justify-between p-6 border-b border-slate-100">
            <h3 class="font-semibold text-slate-900">{{ editing ? '编辑 DDNS 规则' : '添加 DDNS 规则' }}</h3>
            <button @click="modal=null" class="btn-ghost btn-sm"><X :size="16" /></button>
          </div>
          <div class="p-6 space-y-4 max-h-[75vh] overflow-y-auto">

            <div>
              <label class="input-label">规则名称</label>
              <input v-model="form.name" class="input" placeholder="My DDNS" />
            </div>

            <div class="grid grid-cols-2 gap-4">
              <div>
                <label class="input-label">DNS 服务商</label>
                <select v-model="form.provider" class="select">
                  <option value="cloudflare">Cloudflare</option>
                  <option value="alidns">阿里云 DNS</option>
                  <option value="dnspod">DNSPod</option>
                  <option value="tencentcloud">腾讯云 DNS</option>
                </select>
              </div>
              <div>
                <label class="input-label">IP 版本</label>
                <select v-model="form.ip_version" class="select">
                  <option value="ipv4">IPv4</option>
                  <option value="ipv6">IPv6</option>
                </select>
              </div>
            </div>

            <!-- IP detection mode -->
            <div>
              <label class="input-label">IP 获取方式</label>
              <div class="grid grid-cols-2 gap-3">
                <button type="button" @click="form.ip_detect_mode='api'"
                        :class="['p-3 rounded-xl border-2 text-left transition-all', form.ip_detect_mode!=='iface' ? 'border-vane-500 bg-vane-50' : 'border-slate-200 hover:border-vane-300']">
                  <div class="font-semibold text-sm">🌐 外部 API</div>
                  <div class="text-xs text-slate-400 mt-0.5">绕过代理，查询公网 IP</div>
                </button>
                <button type="button" @click="form.ip_detect_mode='iface'"
                        :class="['p-3 rounded-xl border-2 text-left transition-all', form.ip_detect_mode==='iface' ? 'border-vane-500 bg-vane-50' : 'border-slate-200 hover:border-vane-300']">
                  <div class="font-semibold text-sm">🔌 读取网卡</div>
                  <div class="text-xs text-slate-400 mt-0.5">直接读本机网卡 IP</div>
                </button>
              </div>
            </div>

            <!-- Interface selector (iface mode) -->
            <div v-if="form.ip_detect_mode === 'iface'">
              <label class="input-label">网卡名称</label>
              <div class="flex gap-2">
                <select v-if="interfaces.length" v-model="form.ip_interface" class="select flex-1">
                  <option v-for="i in interfaces" :key="i" :value="i">{{ i }}</option>
                </select>
                <input v-else v-model="form.ip_interface" class="input flex-1 font-mono" placeholder="例如 eth0、ens3、ppp0" />
                <button type="button" class="btn-secondary btn-sm whitespace-nowrap" @click="loadInterfaces">
                  <RefreshCw :size="13" /> 刷新
                </button>
              </div>
              <p class="text-xs text-slate-400 mt-1">适合本机有公网 IP 的网卡（PPPoE 拨号、静态公网等）</p>
            </div>

            <!-- Domains textarea -->
            <div>
              <label class="input-label">域名列表（一行一个）</label>
              <textarea v-model="form.domainsText" class="input font-mono text-sm resize-none" rows="4"
                        placeholder="home.example.com&#10;*.example.com&#10;example.com"></textarea>
              <p class="text-xs text-slate-400 mt-1">每行一个完整域名，支持泛域名（*.example.com）</p>
            </div>

            <div>
              <label class="input-label">检测间隔（秒）</label>
              <input v-model.number="form.interval" type="number" min="60" class="input max-w-xs" placeholder="300" />
            </div>

            <!-- Provider config -->
            <template v-if="form.provider === 'cloudflare'">
              <div class="p-4 bg-amber-50 rounded-xl border border-amber-100 space-y-3">
                <h4 class="text-xs font-bold text-amber-700 uppercase tracking-wide">Cloudflare 配置</h4>
                <div>
                  <label class="input-label">API Token</label>
                  <input v-model="form.provider_conf.api_token" class="input font-mono text-xs" placeholder="DNS:Edit 权限的 API Token" />
                </div>
                <div>
                  <label class="input-label">Zone ID</label>
                  <input v-model="form.provider_conf.zone_id" class="input font-mono text-xs" />
                </div>
              </div>
            </template>
            <template v-if="form.provider === 'alidns'">
              <div class="p-4 bg-blue-50 rounded-xl border border-blue-100 space-y-3">
                <h4 class="text-xs font-bold text-blue-700 uppercase tracking-wide">阿里云 DNS 配置</h4>
                <div><label class="input-label">Access Key ID</label><input v-model="form.provider_conf.access_key_id" class="input font-mono text-xs" /></div>
                <div><label class="input-label">Access Key Secret</label><input v-model="form.provider_conf.access_key_secret" class="input font-mono text-xs" type="password" /></div>
              </div>
            </template>
            <template v-if="form.provider === 'dnspod' || form.provider === 'tencentcloud'">
              <div class="p-4 bg-blue-50 rounded-xl border border-blue-100 space-y-3">
                <h4 class="text-xs font-bold text-blue-700 uppercase tracking-wide">{{ form.provider === 'dnspod' ? 'DNSPod' : '腾讯云' }} 配置</h4>
                <div><label class="input-label">SecretId</label><input v-model="form.provider_conf.secret_id" class="input font-mono text-xs" /></div>
                <div><label class="input-label">SecretKey</label><input v-model="form.provider_conf.secret_key" class="input font-mono text-xs" type="password" /></div>
              </div>
            </template>

            <div class="flex items-center gap-3">
              <label class="toggle">
                <input type="checkbox" v-model="form.enabled" />
                <div class="toggle-track"></div><div class="toggle-thumb"></div>
              </label>
              <span class="text-sm text-slate-600">创建后立即启用</span>
            </div>
          </div>
          <div class="flex justify-end gap-3 px-6 pb-6">
            <button class="btn-secondary" @click="modal=null">取消</button>
            <button class="btn-primary" @click="save">{{ editing ? '保存' : '创建' }}</button>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Plus, Globe, Pencil, Trash2, X, RefreshCw } from 'lucide-vue-next'
import { api } from '@/stores/auth'
import ProviderBadge from '@/components/ProviderBadge.vue'

const rules = ref([])
const modal = ref(null)
const editing = ref(false)
const form = ref({})
const interfaces = ref([])

function effectiveDomains(rule) {
  if (rule.domains?.length) return rule.domains
  if (rule.domain) {
    const fqdn = rule.sub_domain && rule.sub_domain !== '@'
      ? rule.sub_domain + '.' + rule.domain : rule.domain
    return [fqdn]
  }
  return []
}

function defaultForm() {
  return {
    name: '', provider: 'cloudflare', domainsText: '',
    ip_version: 'ipv4', ip_detect_mode: 'api', ip_interface: '',
    interval: 300, enabled: true, provider_conf: {}
  }
}

async function load() {
  const { data } = await api.get('/ddns')
  rules.value = data
}

async function loadInterfaces() {
  try {
    const { data } = await api.get('/ddns/interfaces')
    interfaces.value = data || []
    if (interfaces.value.length && !form.value.ip_interface) {
      form.value.ip_interface = interfaces.value[0]
    }
  } catch {}
}

function openModal(rule = null) {
  editing.value = !!rule
  if (rule) {
    const domains = rule.domains?.length ? rule.domains : effectiveDomains(rule)
    form.value = {
      ...rule,
      provider_conf: { ...rule.provider_conf },
      domainsText: domains.join('\n'),
      ip_detect_mode: rule.ip_detect_mode || 'api',
      ip_interface: rule.ip_interface || '',
    }
  } else {
    form.value = defaultForm()
  }
  modal.value = true
  loadInterfaces()
}

async function save() {
  const domains = form.value.domainsText
    .split('\n').map(s => s.trim()).filter(Boolean)
  const payload = { ...form.value, domains, domainsText: undefined }
  if (editing.value) {
    await api.put(`/ddns/${form.value.id}`, payload)
  } else {
    await api.post('/ddns', payload)
  }
  modal.value = null
  await load()
}

async function toggle(id) { await api.post(`/ddns/${id}/toggle`); await load() }
async function refresh(id) { await api.post(`/ddns/${id}/refresh`); setTimeout(load, 800) }
async function del(id) {
  if (!confirm('确认删除此 DDNS 规则？')) return
  await api.delete(`/ddns/${id}`); await load()
}

onMounted(load)
</script>
