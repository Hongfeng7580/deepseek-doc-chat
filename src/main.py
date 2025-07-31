import os
import re
import json
import uuid
import textwrap
import requests
import shutil
import glob  # 用于文件搜索
import traceback  # 添加错误堆栈跟踪
import hashlib  # 添加缺失的导入
from datetime import datetime, timedelta  # 添加缺失的导入
from openai import OpenAI
from docx import Document
import chardet
import tiktoken  # 用于Token计数
import base64  # 用于简单的密钥混淆
from Crypto.Cipher import AES  # 添加AES加密
from Crypto.Random import get_random_bytes  # 添加安全随机数生成
# 添加在import语句之前
import sys

# 解决PyInstaller打包时tiktoken的路径问题
if getattr(sys, 'frozen', False):
    tiktoken_cache_dir = os.path.join(sys._MEIPASS, 'tiktoken_cache')
    os.environ['TIKTOKEN_CACHE_DIR'] = tiktoken_cache_dir


class APIKeyManager:
    def __init__(self, key_file="api_keys.enc", master_key=None):
        self.key_file = key_file
        self.keys = {}
        self.master_key = master_key
        self.key_usage = {}  # 跟踪密钥使用情况
        self.load_keys()
    
    def _derive_key(self, salt):
        """从主密码派生加密密钥"""
        if not self.master_key:
            raise ValueError("主密码未设置")
        return hashlib.pbkdf2_hmac(
            'sha256', 
            self.master_key.encode(), 
            salt, 
            100000,  # 高迭代次数增加暴力破解难度
            32  # AES-256密钥长度
        )
    
    def _encrypt(self, plaintext):
        """AES加密数据"""
        salt = get_random_bytes(16)  # 随机盐值
        key = self._derive_key(salt)
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
        return salt + cipher.nonce + tag + ciphertext
    
    def _decrypt(self, ciphertext):
        """AES解密数据"""
        salt = ciphertext[:16]
        nonce = ciphertext[16:32]
        tag = ciphertext[32:48]
        ciphertext = ciphertext[48:]
        
        key = self._derive_key(salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode()
        except ValueError:
            raise ValueError("解密失败 - 可能是主密码错误")
    
    def load_keys(self):
        """从加密文件加载API密钥"""
        if os.path.exists(self.key_file):
            try:
                with open(self.key_file, 'rb') as f:
                    encrypted_data = f.read()
                decrypted_data = self._decrypt(encrypted_data)
                data = json.loads(decrypted_data)
                self.keys = data.get("keys", {})
                self.key_usage = data.get("usage", {})
                print(f"🔑 已加载 {len(self.keys)} 个API密钥")
            except Exception as e:
                print(f"❌ 加载API密钥失败: {str(e)}")
                self.keys = {}
                self.key_usage = {}
    
    def save_keys(self):
        """保存API密钥到加密文件"""
        try:
            data = {
                "keys": self.keys,
                "usage": self.key_usage,
                "last_updated": datetime.now().isoformat()
            }
            plaintext = json.dumps(data)
            encrypted_data = self._encrypt(plaintext)
            
            with open(self.key_file, 'wb') as f:
                f.write(encrypted_data)
            print(f"💾 API密钥已安全保存到: {self.key_file}")
            return True
        except Exception as e:
            print(f"❌ 保存API密钥失败: {str(e)}")
            return False
    
    def set_master_key(self, master_key):
        """设置主密码"""
        self.master_key = master_key
        # 验证主密码
        if os.path.exists(self.key_file):
            try:
                self.load_keys()
                return True
            except:
                return False
        return True
    
    def add_key(self, alias, key, valid_days=90):
        """添加新的API密钥并设置有效期"""
        if alias in self.keys:
            print(f"❌ 别名 '{alias}' 已存在")
            return False
        
        # 记录添加时间
        self.keys[alias] = {
            "key": key,
            "created": datetime.now().isoformat(),
            "expires": (datetime.now() + timedelta(days=valid_days)).isoformat(),
            "last_used": None
        }
        
        # 初始化使用统计
        self.key_usage[alias] = {
            "use_count": 0,
            "last_used": None,
            "usage_history": []
        }
        
        self.save_keys()
        print(f"✅ 已添加API密钥: {alias} (有效期至 {self.keys[alias]['expires'][:10]})")
        return True
    
    def edit_key(self, alias, new_key):
        """编辑现有API密钥"""
        if alias not in self.keys:
            print(f"❌ 别名 '{alias}' 不存在")
            return False
        
        self.keys[alias]["key"] = new_key
        self.save_keys()
        print(f"✅ 已更新API密钥: {alias}")
        return True
    
    def delete_key(self, alias):
        """删除API密钥"""
        if alias not in self.keys:
            print(f"❌ 别名 '{alias}' 不存在")
            return False
        
        del self.keys[alias]
        if alias in self.key_usage:
            del self.key_usage[alias]
        
        self.save_keys()
        print(f"🗑️ 已删除API密钥: {alias}")
        return True
    
    def list_keys(self):
        """列出所有API密钥及其状态"""
        return list(self.keys.keys())
    
    def get_key(self, alias):
        """获取指定别名的API密钥"""
        if alias in self.keys:
            key_info = self.keys[alias]
            
            # 检查密钥是否过期
            expires = datetime.fromisoformat(key_info["expires"])
            if datetime.now() > expires:
                print(f"⚠️ 警告: 密钥 '{alias}' 已过期 ({expires.date()})")
                return None
            
            # 更新使用统计
            self.key_usage[alias]["use_count"] += 1
            self.key_usage[alias]["last_used"] = datetime.now().isoformat()
            self.key_usage[alias]["usage_history"].append({
                "timestamp": datetime.now().isoformat(),
                "action": "used"
            })
            self.save_keys()
            
            return key_info["key"]
        return None
    
    def get_key_info(self, alias):
        """获取密钥详细信息"""
        if alias in self.keys:
            key_info = self.keys[alias].copy()
            key_info["usage"] = self.key_usage.get(alias, {})
            return key_info
        return None
    
    def rotate_keys(self):
        """轮换过期密钥"""
        rotated = 0
        for alias, key_info in list(self.keys.items()):
            expires = datetime.fromisoformat(key_info["expires"])
            if datetime.now() > expires:
                self.delete_key(alias)
                rotated += 1
        return rotated
    
    def add_usage_record(self, alias, action):
        """添加密钥使用记录"""
        if alias in self.key_usage:
            self.key_usage[alias]["usage_history"].append({
                "timestamp": datetime.now().isoformat(),
                "action": action
            })
            self.save_keys()

def display_master_key_menu():
    """显示主密码菜单"""
    print("\n" + "=" * 30)
    print("主密码设置")
    print("=" * 30)
    print("1. 设置主密码")
    print("2. 更改主密码")
    print("3. 返回")
    print("=" * 30)
    return input("请选择操作: ")

def master_key_management(key_manager):
    """主密码管理功能"""
    while True:
        choice = display_master_key_menu()
        
        if choice == '1':  # 设置主密码
            if key_manager.master_key:
                print("❌ 主密码已设置，请使用更改功能")
                continue
                
            master_key = input("设置主密码: ")
            confirm = input("确认主密码: ")
            
            if master_key != confirm:
                print("❌ 两次输入的密码不匹配")
                continue
                
            if key_manager.set_master_key(master_key):
                print("✅ 主密码设置成功")
            else:
                print("❌ 主密码设置失败")
                
        elif choice == '2':  # 更改主密码
            if not key_manager.master_key:
                print("❌ 尚未设置主密码")
                continue
                
            current = input("输入当前主密码: ")
            if current != key_manager.master_key:
                print("❌ 当前密码不正确")
                continue
                
            new_key = input("设置新主密码: ")
            confirm = input("确认新主密码: ")
            
            if new_key != confirm:
                print("❌ 两次输入的密码不匹配")
                continue
                
            key_manager.set_master_key(new_key)
            key_manager.save_keys()
            print("✅ 主密码已更新")
            
        elif choice == '3':  # 返回
            break
            
        else:
            print("❌ 无效选择")


class DeepSeekChatManager:
    def __init__(self, api_key):
        self.api_key = api_key
        self.client = OpenAI(
            api_key=self.api_key,
            base_url="https://api.deepseek.com"
        )
        # 对话管理
        self.current_conversation = []
        self.session_id = None
        self.system_prompt = "你是一个知识渊博的AI助手"
        self.thinking_steps = []
        self.model = "deepseek-reasoner"
        self.total_tokens = 0  # Token统计
        
        # 文件管理
        self.log_dir = "conversation_logs"
        self.error_dir = "error_logs"
        self.doc_backup_dir = "document_backups"
        self.session_history_dir = "session_history"  # 会话历史目录
        self.current_log_file = None
        os.makedirs(self.log_dir, exist_ok=True)
        os.makedirs(self.error_dir, exist_ok=True)
        os.makedirs(self.doc_backup_dir, exist_ok=True)
        os.makedirs(self.session_history_dir, exist_ok=True)
        self.available_models = [
            "deepseek-reasoner",
            "deepseek-coder",
            "deepseek-math",
            "deepseek-chat"
        ]
        self.current_model = "deepseek-reasoner"
        self.max_tokens = 2000  # 默认Token限制

    def verify_api_key(self, api_key):
        """验证API密钥有效性"""
        try:
            client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com")
            client.models.list()
            return True
        except:
            return False

    def set_model(self, model_name):
        """设置使用的模型"""
        if model_name in self.available_models:
            self.current_model = model_name
            print(f"✅ 模型已切换为: {model_name}")
        else:
            print(f"❌ 无效模型: {model_name}")
    
    def set_max_tokens(self, max_tokens):
        """设置最大Token限制"""
        try:
            self.max_tokens = int(max_tokens)
            print(f"✅ Token限制已设置为: {self.max_tokens}")
        except ValueError:
            print("❌ 请输入有效的数字")
    
    def extract_document_content(self, file_path, extraction_mode="full"):
        """根据选择的模式提取文档内容"""
        try:
            raw_content = extract_text_from_file(file_path)
            
            if extraction_mode == "full":
                return raw_content
            
            elif extraction_mode == "summary":
                # 使用AI生成摘要
                summary = self.generate_summary(raw_content)
                return f"文档摘要:\n{summary}\n\n完整内容请查看源文件"
            
            elif extraction_mode == "key_sections":
                # 提取关键部分（前1/3）
                lines = raw_content.split('\n')
                key_lines = lines[:len(lines)//3]
                return "\n".join(key_lines)
            
            return raw_content
        except Exception as e:
            error_msg = f"提取文档内容失败: {str(e)}"
            print(f"❌ {error_msg}")
            self._log_error(error_msg, "ERROR", traceback.format_exc())
            return None
    
    def generate_summary(self, content, max_length=500):
        """使用AI生成文档摘要"""
        # 简化实现 - 实际应用中应该调用AI模型
        return content[:max_length] + ("..." if len(content) > max_length else "")
    
    def delete_session(self, session_id):
        """删除保存的会话"""
        session_file = os.path.join(self.session_history_dir, f"session_{session_id}.json")
        if os.path.exists(session_file):
            try:
                os.remove(session_file)
                print(f"🗑️ 会话已删除: {session_id}")
                return True
            except Exception as e:
                error_msg = f"删除会话失败: {str(e)}"
                print(f"❌ {error_msg}")
                self._log_error(error_msg, "ERROR", traceback.format_exc())
                return False
        else:
            error_msg = f"会话文件不存在: {session_file}"
            print(f"❌ {error_msg}")
            self._log_error(error_msg, "WARNING")
            return False
    
    def rename_session(self, session_id, new_name):
        """重命名会话"""
        session_file = os.path.join(self.session_history_dir, f"session_{session_id}.json")
        if os.path.exists(session_file):
            try:
                with open(session_file, 'r', encoding='utf-8') as f:
                    session_data = json.load(f)
                
                # 添加新名称
                session_data["custom_name"] = new_name
                
                with open(session_file, 'w', encoding='utf-8') as f:
                    json.dump(session_data, f, ensure_ascii=False, indent=2)
                
                print(f"✏️ 会话已重命名为: {new_name}")
                return True
            except Exception as e:
                error_msg = f"重命名会话失败: {str(e)}"
                print(f"❌ {error_msg}")
                self._log_error(error_msg, "ERROR", traceback.format_exc())
                return False
        else:
            error_msg = f"会话文件不存在: {session_file}"
            print(f"❌ {error_msg}")
            self._log_error(error_msg, "WARNING")
            return False

    
    def _get_timestamp(self):
        """获取当前时间戳"""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def _get_date(self):
        """获取当前日期"""
        return datetime.now().strftime("%Y-%m-%d")
    
    def _get_month(self):
        """获取当前月份"""
        return datetime.now().strftime("%Y-%m")
    
    def _log_error(self, error_message, level="ERROR", stack_trace=None, source_function=None):
        """记录错误到错误日志文件，支持不同级别和堆栈跟踪"""
        month_str = self._get_month()
        error_file = os.path.join(self.error_dir, f"{month_str}_errors.txt")
        
        try:
            # 获取调用函数名
            if not source_function:
                try:
                    source_function = traceback.extract_stack(None, 2)[0][2]
                except:
                    source_function = "unknown"
            
            with open(error_file, "a", encoding="utf-8") as f:
                timestamp = self._get_timestamp()
                session_info = f" | 会话ID: {self.session_id}" if self.session_id else ""
                f.write(f"[{timestamp}] [{level}] [函数: {source_function}]{session_info}\n")
                f.write(f"消息: {error_message}\n")
                
                if stack_trace:
                    f.write(f"堆栈跟踪:\n{stack_trace}\n")
                
                f.write("-" * 80 + "\n")
            print(f"⚠️ {level}已记录到: {error_file}")
        except Exception as e:
            print(f"❌ 记录错误时出错: {str(e)}")
    
    def set_system_prompt(self, prompt):
        """设置系统提示词"""
        self.system_prompt = prompt
        print(f"✅ 系统提示词已更新: {prompt}")
    
    def start_new_conversation(self):
        """开始新对话并创建日志文件"""
        # 如果已有对话，先保存
        if self.session_id:
            self.stop_conversation()
        
        # 创建新的对话记录
        self.current_conversation = [
            {
                "role": "system", 
                "content": self.system_prompt,
                "timestamp": self._get_timestamp()
            }
        ]
        self.session_id = str(uuid.uuid4())
        self.thinking_steps = []
        
        # 创建新的日志文件
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_filename = f"conversation_{timestamp}_{self.session_id[:8]}.txt"
        self.current_log_file = os.path.join(self.log_dir, log_filename)
        
        # 写入文件头
        try:
            with open(self.current_log_file, "w", encoding="utf-8") as f:
                f.write(f"会话ID: {self.session_id}\n")
                f.write(f"系统提示: {self.system_prompt}\n")
                f.write(f"开始时间: {self.current_conversation[0]['timestamp']}\n")
                f.write(f"{'=' * 80}\n\n")
        except Exception as e:
            error_msg = f"创建日志文件失败: {str(e)}"
            print(f"❌ {error_msg}")
            self._log_error(error_msg, "CRITICAL", traceback.format_exc(), "start_new_conversation")
            self.current_log_file = None
        
        print(f"✅ 新对话已开始 | 会话ID: {self.session_id}")
        print(f"📝 对话日志保存至: {self.current_log_file}")
        return self.session_id

    def clean_text(self, text):
        """清理和规范化文本"""
        # 替换特殊字符
        text = re.sub(r'[^\x00-\x7F]+', ' ', text)
        # 替换多个空格
        text = re.sub(r'\s+', ' ', text)
        # 截断过长的文本（可根据需要调整）
        return text[:20000]
    
    def backup_document(self, file_path):
        """备份文档到备份目录"""
        if not os.path.isfile(file_path):
            return None
        
        # 创建备份路径
        filename = os.path.basename(file_path)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"{timestamp}_{filename}"
        backup_path = os.path.join(self.doc_backup_dir, backup_filename)

        try:
            # 复制文件
            shutil.copy2(file_path, backup_path)
            print(f"📂 文档已备份至: {backup_path}")
            return backup_path
        except Exception as e:
            error_msg = f"备份文档失败: {str(e)}"
            print(f"❌ {error_msg}")
            self._log_error(error_msg, "ERROR", traceback.format_exc(), "backup_document")
            return None
        
    def count_tokens(self, text):
        """使用tiktoken计算文本的token数量"""
        try:
            encoding = tiktoken.encoding_for_model("gpt-4")
            return len(encoding.encode(text))
        except:
            # 回退方法：粗略估计
            return len(text) // 4
    
    def send_message(self, message, document_content=None, temperature=0.7, max_tokens=2000):
        """发送消息到DeepSeek API并实时记录（支持流式传输）"""
        if not self.session_id:
            self.start_new_conversation()
            
        try:
            # 构建完整消息
            full_message = message
            if document_content:
                full_message += f"\n\n[文档内容]:\n{document_content}"
            
            # 添加用户消息到对话历史
            user_msg = {
                "role": "user",
                "content": full_message,
                "timestamp": self._get_timestamp(),
                "has_document": document_content is not None
            }
            self.current_conversation.append(user_msg)
            
            # 实时写入用户消息到日志文件
            if self.current_log_file:
                try:
                    with open(self.current_log_file, "a", encoding="utf-8") as f:
                        f.write(f"[用户 @ {user_msg['timestamp']}]:\n")
                        if user_msg.get("has_document"):
                            f.write("📎 包含文档内容\n")
                        content = textwrap.fill(user_msg['content'], width=100)
                        f.write(f"{content}\n\n")
                        f.write(f"{'-' * 80}\n\n")
                except Exception as e:
                    error_msg = f"写入日志失败: {str(e)}"
                    print(f"❌ {error_msg}")
                    self._log_error(error_msg, "ERROR", traceback.format_exc(), "send_message")
            
            # 准备API请求
            api_messages = [{"role": msg["role"], "content": msg["content"]} 
                            for msg in self.current_conversation]
            
            # 计算输入Token数
            input_tokens = sum(self.count_tokens(msg['content']) for msg in api_messages)
            self.total_tokens += input_tokens
        
            # 调用API（启用流式传输）
            response = self.client.chat.completions.create(
                model=self.model,
                messages=api_messages,
                temperature=temperature,
                max_tokens=max_tokens,
                stream=True
            )
            
            # 处理流式响应
            collected_chunks = []
            collected_messages = []
            print("\n🤖 AI助手回复: ", end="", flush=True)
            
            try:
                for chunk in response:
                    if chunk.choices and chunk.choices[0].delta and chunk.choices[0].delta.content:
                        chunk_message = chunk.choices[0].delta.content
                        collected_messages.append(chunk_message)
                        print(chunk_message, end="", flush=True)
                    collected_chunks.append(chunk)
            except KeyboardInterrupt:
                print("\n\n⚠️ 用户中断了AI回复")
                # 即使中断，我们也收集到目前已经接收到的部分
                finish_reason = "user_interrupt"
            else:
                # 获取结束原因
                if collected_chunks:
                    last_chunk = collected_chunks[-1]
                    finish_reason = last_chunk.choices[0].finish_reason if last_chunk.choices else "unknown"
                else:
                    finish_reason = "unknown"
        
            print("\n")  # 在流式输出后添加换行
        
            # 获取完整的AI回复
            ai_response = ''.join([m for m in collected_messages if m is not None])
        
            
            # 收集思考过程
            if 'finish_reason' in locals() and finish_reason == "user_interrupt":
                thinking = "用户中断了AI回复"
            else:
                thinking = self.interpret_finish_reason(finish_reason)
            
            # 添加AI回复到对话历史
            ai_msg = {
                "role": "assistant",
                "content": ai_response,
                "timestamp": self._get_timestamp(),
                "thinking": thinking
            }
            self.current_conversation.append(ai_msg)
            
            # 写入AI回复到日志文件
            if self.current_log_file:
                try:
                    with open(self.current_log_file, "a", encoding="utf-8") as f:
                        f.write(f"[AI助手 @ {ai_msg['timestamp']}]:\n")
                        content = textwrap.fill(ai_msg['content'], width=100)
                        f.write(f"{content}\n\n")
                        if ai_msg.get("thinking"):
                            f.write(f"💭 思考过程: {ai_msg['thinking']}\n")
                        f.write(f"{'-' * 80}\n\n")
                except Exception as e:
                    error_msg = f"写入日志失败: {str(e)}"
                    print(f"❌ {error_msg}")
                    self._log_error(error_msg, "ERROR", traceback.format_exc(), "send_message")
            
            return ai_response
        
        except Exception as e:
            error_msg = f"API请求失败: {str(e)}"
            print(f"❌ {error_msg}")
            self._log_error(error_msg, "CRITICAL", traceback.format_exc(), "send_message")
            return None
    
    def interpret_finish_reason(self, reason):
        """解释完成原因作为思考过程"""
        reasons = {
            "stop": "思考过程完成",
            "length": "思考过程因长度限制被截断",
            "content_filter": "思考过程被内容过滤器中断",
            "function_call": "思考过程以函数调用结束",
            "tool_calls": "思考过程以工具调用结束"
        }
        return reasons.get(reason, f"未知完成原因: {reason}")
    
    def highlight_document_references(self, response, document_content):
        """在回复中高亮显示文档引用部分"""
        # 简单实现：在包含文档关键词的句子前添加标记
        highlighted = []
        doc_keywords = set(re.findall(r'\b\w{4,}\b', document_content[:500]))  # 提取文档关键词
        
        for sentence in re.split(r'(?<=[.!?])\s+', response):
            if any(keyword in sentence for keyword in doc_keywords):
                highlighted.append(f"🔍 {sentence}")
            else:
                highlighted.append(sentence)
        
        return ' '.join(highlighted)
    
    def save_session(self):
        """保存当前会话到文件"""
        if not self.session_id:
            return False
        
        session_file = os.path.join(self.session_history_dir, f"session_{self.session_id}.json")
        try:
            with open(session_file, 'w', encoding='utf-8') as f:
                json.dump({
                    "session_id": self.session_id,
                    "system_prompt": self.system_prompt,
                    "conversation": self.current_conversation,
                    "created_at": self._get_timestamp()
                }, f, ensure_ascii=False, indent=2)
            print(f"💾 会话已保存: {session_file}")
            return True
        except Exception as e:
            error_msg = f"保存会话失败: {str(e)}"
            print(f"❌ {error_msg}")
            self._log_error(error_msg, "ERROR", traceback.format_exc(), "save_session")
            return False
    
    def load_session(self, session_id):
        """从文件加载会话"""
        session_file = os.path.join(self.session_history_dir, f"session_{session_id}.json")
        if not os.path.exists(session_file):
            error_msg = f"会话文件不存在: {session_file}"
            print(f"❌ {error_msg}")
            self._log_error(error_msg, "WARNING")
            return False
        
        try:
            with open(session_file, 'r', encoding='utf-8') as f:
                session_data = json.load(f)
            
            self.session_id = session_data["session_id"]
            self.system_prompt = session_data["system_prompt"]
            self.current_conversation = session_data["conversation"]
            
            # 创建新的日志文件
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_filename = f"conversation_{timestamp}_{self.session_id[:8]}.txt"
            self.current_log_file = os.path.join(self.log_dir, log_filename)
            
            # 写入文件头
            with open(self.current_log_file, "w", encoding="utf-8") as f:
                f.write(f"会话ID: {self.session_id}\n")
                f.write(f"系统提示: {self.system_prompt}\n")
                f.write(f"加载时间: {self._get_timestamp()}\n")
                f.write(f"原始创建时间: {session_data['created_at']}\n")
                f.write(f"{'=' * 80}\n\n")
            
            # 写入已加载的对话历史
            with open(self.current_log_file, "a", encoding="utf-8") as f:
                for msg in self.current_conversation[1:]:  # 跳过系统提示
                    role = "用户" if msg["role"] == "user" else "AI助手"
                    f.write(f"[{role} @ {msg['timestamp']}]:\n")
                    if msg.get("has_document"):
                        f.write("📎 包含文档内容\n")
                    content = textwrap.fill(msg['content'], width=100)
                    f.write(f"{content}\n\n")
                    if msg.get("thinking"):
                        f.write(f"💭 思考过程: {msg['thinking']}\n")
                    f.write(f"{'-' * 80}\n\n")
            
            print(f"✅ 会话已加载 | 会话ID: {self.session_id}")
            print(f"📝 对话日志保存至: {self.current_log_file}")
            return True
        except Exception as e:
            error_msg = f"加载会话失败: {str(e)}"
            print(f"❌ {error_msg}")
            self._log_error(error_msg, "ERROR", traceback.format_exc(), "load_session")
            return False
    
    def list_sessions(self):
        """列出所有保存的会话"""
        session_files = glob.glob(os.path.join(self.session_history_dir, "session_*.json"))
        if not session_files:
            print("ℹ️ 没有找到保存的会话")
            return []
        
        sessions = []
        for file_path in session_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    session_data = json.load(f)
                sessions.append({
                    "id": session_data["session_id"],
                    "created": session_data["created_at"],
                    "messages": len(session_data["conversation"]) - 1,  # 排除系统提示
                    "custom_name": session_data.get("custom_name", "")
                })
            except Exception as e:
                error_msg = f"加载会话文件失败: {file_path}, 错误: {str(e)}"
                print(f"❌ {error_msg}")
                self._log_error(error_msg, "WARNING")
                continue
        
        return sessions
    
    def stop_conversation(self):
        """停止当前对话并保存记录"""
        if self.session_id:
            # 保存会话到文件
            self.save_session()
            print(f"🛑 对话已停止 | 会话ID: {self.session_id}")
            self.session_id = None
            self.current_conversation = []
            self.thinking_steps = []
            self.current_log_file = None
        else:
            print("⚠️ 没有正在进行的对话")
    
    def search_document_content(self, document_content, query, case_sensitive=False, use_regex=False):
        """
        在文档内容中搜索关键词
        支持正则表达式和大小写敏感选项
        返回格式: [
            {
                "line": 行号,
                "position": 匹配位置,
                "context": 上下文内容,
                "match": 匹配内容
            }
        ]
        """
        if not document_content or not query:
            return []
        
        try:
            results = []
            lines = document_content.split('\n')
            
            # 设置匹配标志
            flags = 0 if case_sensitive else re.IGNORECASE
            
            # 添加最大结果限制
            MAX_RESULTS = 1000
            
            for i, line in enumerate(lines):
                # 普通文本搜索
                if not use_regex:
                    if case_sensitive:
                        if query in line:
                            start_pos = line.find(query)
                            results.append(self._create_match_result(i, line, start_pos, query))
                    else:
                        if query.lower() in line.lower():
                            start_pos = line.lower().find(query.lower())
                            results.append(self._create_match_result(i, line, start_pos, query))
                # 正则表达式搜索
                else:
                    try:
                        pattern = re.compile(query, flags)
                        for match in pattern.finditer(line):
                            start_pos = match.start()
                            matched_text = match.group()
                            results.append(self._create_match_result(i, line, start_pos, matched_text))
                    except re.error as e:
                        print(f"❌ 正则表达式错误: {str(e)}")
                        return []
                
                # 检查结果数量限制
                if len(results) >= MAX_RESULTS:
                    print(f"⚠️ 达到最大搜索结果限制({MAX_RESULTS})，停止搜索")
                    break
            
            return results
        except Exception as e:
            error_msg = f"文档搜索失败: {str(e)}"
            print(f"❌ {error_msg}")
            self._log_error(error_msg, "ERROR", traceback.format_exc(), "search_document_content")
            return []
    
    def _create_match_result(self, line_num, line_content, position, matched_text):
        """创建匹配结果对象"""
        # 显示上下文（前后各2行）
        context_lines = []
        start = max(0, line_num - 2)
        end = min(len(line_content.split('\n')), line_num + 3)
        
        # 构建上下文，高亮匹配行
        for i in range(start, end):
            context_line = line_content.split('\n')[i] if i < len(line_content.split('\n')) else ""
            if i == line_num:
                # 高亮匹配部分
                if position >= 0 and position + len(matched_text) <= len(context_line):
                    highlighted = (
                        context_line[:position] +
                        f"\033[91m{context_line[position:position+len(matched_text)]}\033[0m" +
                        context_line[position+len(matched_text):]
                    )
                    context_lines.append(f"{i+1}: {highlighted}")
                else:
                    context_lines.append(f"{i+1}: {context_line}")
            else:
                context_lines.append(f"{i+1}: {context_line}")
        
        return {
            "line": line_num + 1,
            "position": position + 1,
            "context": '\n'.join(context_lines),
            "match": matched_text
        }

def extract_text_from_file(file_path):
    """
    根据文件扩展名提取文本内容
    支持格式: .txt, .docx, .pdf
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"文件未找到: {file_path}")

    ext = os.path.splitext(file_path)[1].lower()

    try:
        if ext == '.txt':
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()

        elif ext == '.docx':
            doc = Document(file_path)
            return '\n'.join([para.text for para in doc.paragraphs])

        elif ext == '.pdf':
            try:
                # 添加更健壮的PDF处理
                with open(file_path, 'rb') as f:
                    reader = PyPDF2.PdfReader(f)
                    text = []
                    for page in reader.pages:
                        # 添加错误处理
                        try:
                            text.append(page.extract_text() or "")
                        except Exception as e:
                            print(f"❌ 提取PDF页面失败: {str(e)}")
                    return '\n'.join(text)
            except Exception as e:
                raise Exception(f"处理PDF文件时出错: {str(e)}")
            

    except Exception as e:
        raise Exception(f"提取文件内容时出错: {str(e)}")

def display_menu():
    """显示主菜单"""
    print("\n" + "=" * 60)
    print("DeepSeek 文档对话管理系统")
    print("=" * 60)
    print("1. 设置系统提示词")
    print("2. 开始新对话")
    print("3. 发送普通消息")
    print("4. 处理文档并提问")
    print("5. 停止并保存当前对话")
    print("6. 查看错误日志")
    print("7. 查看当前对话历史")
    print("8. 保存当前会话")
    print("9. 管理历史会话")
    print("10. 在文档中搜索")
    print("11. 配置选项")
    print("12. 退出程序")
    print("=" * 60)
    return input("请选择操作: ")

def display_config_menu():
    """显示配置菜单"""
    print("\n" + "=" * 30)
    print("配置选项")
    print("=" * 30)
    print("1. 设置AI模型")
    print("2. 设置Token限制")
    print("3. 返回主菜单")
    print("=" * 30)
    return input("请选择操作: ")

def display_session_management_menu():
    """显示会话管理菜单"""
    print("\n" + "=" * 30)
    print("会话管理")
    print("=" * 30)
    print("1. 加载会话")
    print("2. 重命名会话")
    print("3. 删除会话")
    print("4. 返回主菜单")
    print("=" * 30)
    return input("请选择操作: ")

def display_document_extraction_menu():
    """显示文档提取选项菜单"""
    print("\n" + "=" * 30)
    print("文档处理选项")
    print("=" * 30)
    print("1. 完整文档内容")
    print("2. 文档摘要")
    print("3. 关键部分提取")
    print("=" * 30)
    return input("请选择处理方式: ")

def display_search_options_menu():
    """显示文档搜索选项菜单"""
    print("\n" + "=" * 30)
    print("文档搜索选项")
    print("=" * 30)
    print("1. 当前文档")
    print("2. 所有会话文档")
    print("3. 外部文件")
    print("4. 返回主菜单")
    print("=" * 30)
    return input("请选择搜索范围: ")

def display_search_settings_menu():
    """显示搜索设置菜单"""
    print("\n" + "=" * 30)
    print("搜索设置")
    print("=" * 30)
    print("1. 区分大小写")
    print("2. 不区分大小写 (默认)")
    print("3. 使用正则表达式")
    print("4. 返回")
    print("=" * 30)
    return input("请选择搜索模式: ")

def display_error_log_menu():
    """显示错误日志菜单"""
    print("\n" + "=" * 30)
    print("错误日志选项")
    print("=" * 30)
    print("1. 查看今日错误")
    print("2. 查看历史错误")
    print("3. 返回主菜单")
    print("=" * 30)
    return input("请选择操作: ")

def display_api_key_menu(key_manager):
    """显示API密钥管理菜单"""
    print("\n" + "=" * 30)
    print("API密钥管理")
    print("=" * 30)
    print("1. 添加新密钥")
    print("2. 编辑现有密钥")
    print("3. 删除密钥")
    print("4. 列出所有密钥")
    print("5. 返回主菜单")
    print("=" * 30)
    return input("请选择操作: ")

# 修改 select_api_key 函数
def select_api_key(key_manager):
    """让用户选择API密钥并显示详细信息"""
    keys = key_manager.list_keys()
    if not keys:
        print("⚠️ 没有可用的API密钥，请先添加密钥")
        return None
    
    print("\n可用的API密钥:")
    for i, alias in enumerate(keys):
        key_info = key_manager.get_key_info(alias)
        expires = datetime.fromisoformat(key_info["expires"]).strftime("%Y-%m-%d")
        last_used = key_info["usage"].get("last_used")
        if last_used:
            last_used = datetime.fromisoformat(last_used).strftime("%Y-%m-%d %H:%M")
        else:
            last_used = "从未使用"
        print(f"{i+1}. {alias} (有效期至: {expires}, 上次使用: {last_used})")
    
    try:
        selection = int(input("请选择要使用的API密钥 (0返回): "))
        if selection == 0:
            return None
        if 1 <= selection <= len(keys):
            selected_alias = keys[selection-1]
            key = key_manager.get_key(selected_alias)
            if key:
                key_manager.add_usage_record(selected_alias, "selected")
                return key
            else:
                print("❌ 无法获取密钥，可能已过期")
                return None
    except:
        pass
    
    print("❌ 无效选择")
    return None

# 在 api_key_management 函数中添加密钥有效期设置
def api_key_management(key_manager):
    """API密钥管理功能"""
    while True:
        choice = display_api_key_menu(key_manager)
        
        if choice == '1':  # 添加新密钥
            alias = input("输入密钥别名: ")
            key = input("输入API密钥: ")
            try:
                valid_days = int(input("设置有效期(天)[默认90]: ") or "90")
            except:
                valid_days = 90
            key_manager.add_key(alias, key, valid_days)
            
        elif choice == '2':  # 编辑现有密钥
            keys = key_manager.list_keys()
            if not keys:
                continue
                
            print("\n选择要编辑的密钥:")
            for i, alias in enumerate(keys):
                key_info = key_manager.get_key_info(alias)
                expires = datetime.fromisoformat(key_info["expires"]).strftime("%Y-%m-%d")
                print(f"{i+1}. {alias} (有效期至: {expires})")
            
            try:
                selection = int(input("请选择密钥 (0取消): "))
                if 1 <= selection <= len(keys):
                    alias = keys[selection-1]
                    new_key = input("输入新的API密钥: ")
                    key_manager.edit_key(alias, new_key)
            except:
                print("❌ 无效选择")
                
        elif choice == '3':  # 删除密钥
            keys = key_manager.list_keys()
            if not keys:
                continue
                
            print("\n选择要删除的密钥:")
            for i, alias in enumerate(keys):
                key_info = key_manager.get_key_info(alias)
                expires = datetime.fromisoformat(key_info["expires"]).strftime("%Y-%m-%d")
                print(f"{i+1}. {alias} (有效期至: {expires})")
            
            try:
                selection = int(input("请选择密钥 (0取消): "))
                if 1 <= selection <= len(keys):
                    alias = keys[selection-1]
                    confirm = input(f"确定要删除密钥 '{alias}' 吗? (y/n): ")
                    if confirm.lower() == 'y':
                        key_manager.delete_key(alias)
            except:
                print("❌ 无效选择")
                
        elif choice == '4':  # 列出所有密钥
            keys = key_manager.list_keys()
            if keys:
                print("\n已保存的API密钥:")
                for alias in keys:
                    key_info = key_manager.get_key_info(alias)
                    created = datetime.fromisoformat(key_info["created"]).strftime("%Y-%m-%d")
                    expires = datetime.fromisoformat(key_info["expires"]).strftime("%Y-%m-%d")
                    use_count = key_info["usage"].get("use_count", 0)
                    print(f"- {alias} (创建: {created}, 过期: {expires}, 使用次数: {use_count})")
            else:
                print("ℹ️ 没有保存的API密钥")
                
        elif choice == '5':  # 返回主菜单
            break
            
        else:
            print("❌ 无效选择")
        
def main():

    # 确保程序所在目录有必要的子目录
    required_dirs = [
        "conversation_logs", 
        "error_logs", 
        "document_backups", 
        "session_history"
    ]
    
    for dir_name in required_dirs:
        if not os.path.exists(dir_name):
            os.makedirs(dir_name)
            print(f"📁 创建目录: {dir_name}")

    # 创建API密钥管理器
    key_manager = APIKeyManager()
    
    # 首先处理主密码
    if os.path.exists(key_manager.key_file):
        print("🔒 检测到加密的密钥存储，需要主密码")
        while True:
            master_key = input("请输入主密码: ")
            if key_manager.set_master_key(master_key):
                print("✅ 主密码验证成功")
                break
            else:
                print("❌ 主密码错误")
                retry = input("是否重试? (y/n): ")
                if retry.lower() != 'y':
                    print("👋 程序退出")
                    return
    else:
        print("⚠️ 首次使用，请设置主密码")
        while True:
            master_key = input("设置主密码: ")
            confirm = input("确认主密码: ")
            if master_key == confirm:
                if key_manager.set_master_key(master_key):
                    print("✅ 主密码设置成功")
                    break
                else:
                    print("❌ 主密码设置失败")
            else:
                print("❌ 两次输入的密码不匹配")
    
    # 密钥选择菜单
    selected_key = None
    while not selected_key:
        print("\n" + "=" * 60)
        print("DeepSeek 文档对话管理系统")
        print("=" * 60)
        print("1. 选择API密钥")
        print("2. 管理API密钥")
        print("3. 主密码管理")
        print("4. 退出程序")
        print("=" * 60)
        choice = input("请选择操作: ")
        
        if choice == '1':
            selected_key = select_api_key(key_manager)
            # 验证密钥有效性
            if selected_key:
                manager = DeepSeekChatManager(selected_key)
                if not manager.verify_api_key(selected_key):
                    print("❌ API密钥无效或无法连接到DeepSeek API")
                    # 这里不需要记录无效密钥，因为get_key()方法已记录
                    selected_key = None
        elif choice == '2':
            api_key_management(key_manager)
        elif choice == '3':
            master_key_management(key_manager)
        elif choice == '4':
            print("👋 程序退出，感谢使用！")
            return
        else:
            print("❌ 无效选择")
    
    # 创建聊天管理器（只创建一次）
    manager = DeepSeekChatManager(selected_key)
    
    # 主循环
    while True:
        choice = display_menu()
        
        if choice == '1':
            prompt = input("请输入系统提示词: ")
            manager.set_system_prompt(prompt)
            
        elif choice == '2':
            manager.start_new_conversation()
            
        elif choice == '3':
            if not manager.session_id:
                print("⚠️ 没有活动对话，正在创建新对话...")
                manager.start_new_conversation()
                
            message = input("请输入你的消息: ")
            response = manager.send_message(message)
            
        elif choice == '4':
            if not manager.session_id:
                print("⚠️ 没有活动对话，正在创建新对话...")
                manager.start_new_conversation()
                
            file_path = input("请输入文档路径: ")
            
            # 让用户选择文档处理方式
            extraction_choice = display_document_extraction_menu()
            extraction_mode = "full"
            
            if extraction_choice == '1':
                extraction_mode = "full"
            elif extraction_choice == '2':
                extraction_mode = "summary"
            elif extraction_choice == '3':
                extraction_mode = "key_sections"
            
            try:
                # 备份文档
                backup_path = manager.backup_document(file_path)
                
                # 根据选择的模式提取文档内容
                document_content = manager.extract_document_content(file_path, extraction_mode)
                
                if document_content:
                    # 显示文档摘要
                    doc_preview = document_content[:300] + ("..." if len(document_content) > 300 else "")
                    print(f"\n📄 文档内容 ({len(document_content)}字符):")
                    print(doc_preview)
                    print("-" * 60)
                    
                    message = input("\n请输入基于文档的问题: ")
                    response = manager.send_message(message, document_content)
                    # 高亮显示文档相关部分
                    highlighted = manager.highlight_document_references(response, document_content)
                    print("\n🌟 高亮回复 (文档相关部分标记为🔍):")
                    print(highlighted)
            except Exception as e:
                print(f"❌ 处理文档失败: {str(e)}")
                
        elif choice == '5':
            manager.stop_conversation()
            
        elif choice == '6':
            log_choice = display_error_log_menu()
            
            if log_choice == '1':  # 今日错误
                date_str = datetime.now().strftime("%Y-%m-%d")
                month_str = datetime.now().strftime("%Y-%m")
                error_file = os.path.join(manager.error_dir, f"{month_str}_errors.txt")
                if os.path.exists(error_file):
                    print(f"\n📝 错误日志 ({month_str}):")
                    with open(error_file, "r", encoding="utf-8") as f:
                        # 只显示今日错误
                        today_errors = []
                        current_error = []
                        for line in f:
                            if line.startswith('[') and date_str in line:
                                if current_error:
                                    today_errors.append(''.join(current_error))
                                current_error = [line]
                            elif line.startswith('[') and date_str not in line:
                                if current_error:
                                    today_errors.append(''.join(current_error))
                                current_error = []
                            elif current_error:
                                current_error.append(line)
                        
                        if current_error:
                            today_errors.append(''.join(current_error))
                        
                        if today_errors:
                            for error in today_errors:
                                print(error)
                        else:
                            print("✅ 今日没有错误记录")
                else:
                    print("✅ 今日没有错误记录")
                    
            elif log_choice == '2':  # 历史错误
                error_files = glob.glob(os.path.join(manager.error_dir, "*_errors.txt"))
                if not error_files:
                    print("✅ 没有历史错误记录")
                    continue
                    
                print("\n📚 历史错误日志:")
                for i, file_path in enumerate(sorted(error_files, reverse=True)):
                    filename = os.path.basename(file_path)
                    print(f"{i+1}. {filename}")
                
                try:
                    selection = int(input("请选择要查看的日志编号 (0取消): "))
                    if 1 <= selection <= len(error_files):
                        print(f"\n📝 {os.path.basename(error_files[selection-1])}:")
                        with open(error_files[selection-1], "r", encoding="utf-8") as f:
                            print(f.read())
                    else:
                        print("操作取消")
                except:
                    print("❌ 无效选择")
            
        elif choice == '7':
            if manager.session_id:
                print("\n📜 当前对话历史:")
                for msg in manager.current_conversation:
                    if msg['role'] == 'system':
                        continue
                    role = "用户" if msg['role'] == 'user' else "AI助手"
                    timestamp = msg.get('timestamp', '未知时间')
                    content_preview = msg['content'][:100] + ("..." if len(msg['content']) > 100 else "")
                    print(f"[{role} @ {timestamp}]:")
                    print(content_preview)
                    if 'thinking' in msg:
                        print(f"💭 {msg['thinking']}")
                    print("-" * 60)
            else:
                print("⚠️ 没有正在进行的对话")
                
        elif choice == '8':  # 保存会话
            if manager.session_id:
                manager.save_session()
            else:
                print("⚠️ 没有正在进行的对话")
                
        elif choice == '9':  # 会话管理
            session_choice = display_session_management_menu()
            
            if session_choice == '1':  # 加载会话
                sessions = manager.list_sessions()
                if not sessions:
                    continue
                    
                print("\n📚 保存的会话列表:")
                for i, session in enumerate(sessions):
                    custom_name = session.get("custom_name", "")
                    name_display = f" - {custom_name}" if custom_name else ""
                    print(f"{i+1}. ID: {session['id']}{name_display} | 创建时间: {session['created']} | 消息数: {session['messages']}")
                
                try:
                    selection = int(input("请选择要加载的会话编号 (0取消): "))
                    if 1 <= selection <= len(sessions):
                        manager.load_session(sessions[selection-1]['id'])
                    else:
                        print("操作取消")
                except:
                    print("❌ 无效选择")
            
            elif session_choice == '2':  # 重命名会话
                sessions = manager.list_sessions()
                if not sessions:
                    continue
                    
                print("\n📚 保存的会话列表:")
                for i, session in enumerate(sessions):
                    custom_name = session.get("custom_name", "")
                    name_display = f" - {custom_name}" if custom_name else ""
                    print(f"{i+1}. ID: {session['id']}{name_display} | 创建时间: {session['created']} | 消息数: {session['messages']}")
                
                try:
                    selection = int(input("请选择要重命名的会话编号 (0取消): "))
                    if 1 <= selection <= len(sessions):
                        new_name = input("请输入新的会话名称: ")
                        manager.rename_session(sessions[selection-1]['id'], new_name)
                    else:
                        print("操作取消")
                except:
                    print("❌ 无效选择")
            
            elif session_choice == '3':  # 删除会话
                sessions = manager.list_sessions()
                if not sessions:
                    continue
                    
                print("\n📚 保存的会话列表:")
                for i, session in enumerate(sessions):
                    custom_name = session.get("custom_name", "")
                    name_display = f" - {custom_name}" if custom_name else ""
                    print(f"{i+1}. ID: {session['id']}{name_display} | 创建时间: {session['created']} | 消息数: {session['messages']}")
                
                try:
                    selection = int(input("请选择要删除的会话编号 (0取消): "))
                    if 1 <= selection <= len(sessions):
                        confirm = input(f"确定要删除会话 '{sessions[selection-1]['id']}' 吗? (y/n): ")
                        if confirm.lower() == 'y':
                            manager.delete_session(sessions[selection-1]['id'])
                        else:
                            print("操作取消")
                    else:
                        print("操作取消")
                except:
                    print("❌ 无效选择")
        
        elif choice == '10':  # 文档搜索
            # 让用户选择搜索范围
            scope_choice = display_search_options_menu()
            
            document_contents = []
            document_sources = []
            
            # 当前文档模式
            if scope_choice == '1':
                if not manager.session_id:
                    print("⚠️ 没有活动对话")
                    continue
                    
                # 查找最近的文档内容
                for msg in reversed(manager.current_conversation):
                    if msg.get('has_document'):
                        # 从消息内容中提取文档部分
                        match = re.search(r'\[文档内容\]:\n(.*)', msg['content'], re.DOTALL)
                        if match:
                            document_contents.append(match.group(1))
                            document_sources.append(f"当前会话 (消息时间: {msg['timestamp']})")
                            break
                
                if not document_contents:
                    print("ℹ️ 当前对话中没有文档内容")
                    continue
            
            # 所有会话文档模式
            elif scope_choice == '2':
                if not manager.session_id:
                    print("⚠️ 没有活动对话")
                    continue
                    
                # 查找所有文档内容
                for msg in manager.current_conversation:
                    if msg.get('has_document'):
                        match = re.search(r'\[文档内容\]:\n(.*)', msg['content'], re.DOTALL)
                        if match:
                            document_contents.append(match.group(1))
                            document_sources.append(f"消息时间: {msg['timestamp']}")
                
                if not document_contents:
                    print("ℹ️ 当前对话中没有文档内容")
                    continue
            
            # 外部文件模式
            elif scope_choice == '3':
                file_path = input("请输入文档路径: ")
                try:
                    document_content = manager.extract_document_content(file_path, "full")
                    if document_content:
                        document_contents.append(document_content)
                        document_sources.append(f"外部文件: {file_path}")
                except Exception as e:
                    print(f"❌ 处理文档失败: {str(e)}")
                    continue
            else:
                continue
            
            # 设置搜索选项
            case_sensitive = False
            use_regex = False
            
            settings_choice = display_search_settings_menu()
            if settings_choice == '1':
                case_sensitive = True
            elif settings_choice == '3':
                use_regex = True
            
            query = input("请输入要搜索的关键词: ")
            
            all_results = []
            for idx, doc_content in enumerate(document_contents):
                results = manager.search_document_content(
                    doc_content, 
                    query, 
                    case_sensitive=case_sensitive, 
                    use_regex=use_regex
                )
                
                for result in results:
                    result["source"] = document_sources[idx]
                    all_results.append(result)
            
            if not all_results:
                print("🔍 未找到匹配结果")
            else:
                print(f"\n🔍 找到 {len(all_results)} 处匹配:")
                
                # 分页显示结果
                page_size = 5
                page = 0
                total_pages = (len(all_results)) // page_size + (1 if len(all_results) % page_size > 0 else 0)
                
                while page < total_pages:
                    start_idx = page * page_size
                    end_idx = min((page + 1) * page_size, len(all_results))
                    
                    print(f"\n=== 第 {page+1}/{total_pages} 页 ===")
                    for i in range(start_idx, end_idx):
                        result = all_results[i]
                        print(f"\n匹配 #{i+1} (来源: {result['source']})")
                        print(f"位置: 行 {result['line']}, 列 {result['position']}")
                        print(result['context'])
                        print("-" * 60)
                    
                    if total_pages > 1:
                        print("\n导航: n-下一页, p-上一页, q-退出")
                        nav = input("> ")
                        if nav.lower() == 'n' and page < total_pages - 1:
                            page += 1
                        elif nav.lower() == 'p' and page > 0:
                            page -= 1
                        elif nav.lower() == 'q':
                            break
                    else:
                        break
        
        elif choice == '11':  # 配置选项
            config_choice = display_config_menu()
            
            if config_choice == '1':  # 设置AI模型
                print("\n可用模型:")
                for i, model in enumerate(manager.available_models):
                    print(f"{i+1}. {model}")
                
                try:
                    selection = int(input("请选择模型 (0取消): "))
                    if 1 <= selection <= len(manager.available_models):
                        manager.set_model(manager.available_models[selection-1])
                    else:
                        print("操作取消")
                except:
                    print("❌ 无效选择")
            
            elif config_choice == '2':  # 设置Token限制
                max_tokens = input(f"当前Token限制: {manager.max_tokens}\n请输入新的Token限制: ")
                manager.set_max_tokens(max_tokens)
        
        elif choice == '12':
            if manager.session_id:
                manager.stop_conversation()
            print("👋 程序退出，感谢使用！")
            break
            
        else:
            print("❌ 无效选择，请重新输入")
    
    # 轮换过期密钥
    rotated = key_manager.rotate_keys()
    if rotated > 0:
        print(f"🔄 已轮换 {rotated} 个过期密钥")


if __name__ == "__main__":
    # 确保安装所需库
    try:
        import openai
        import docx
        import chardet
        import PyPDF2
        import shutil
        import tiktoken  # 新增依赖
    except ImportError as e:
        missing_module = str(e).split(" ")[-1]
        print(f"请先安装所需依赖: pip install {missing_module}")
        exit(1)
    
    try:
        main()
    except Exception as e:
        print(f"程序运行时出错: {str(e)}")
        import traceback
        traceback.print_exc()
        input("按Enter键退出...")


#
#                           _ooOoo_  
#                          o8888888o  
#                          88" . "88  
#                          (| -_- |)  
#                           O\ = /O  
#                       ____/`---'\____  
#                     .   ' \\| |// `.  
#                      / \\||| : |||// \  
#                    / _||||| -:- |||||- \  
#                      | | \\\ - /// | |  
#                    | \_| ''\---/'' | |  
#                     \ .-\__ `-` ___/-. /  
#                  ___`. .' /--.--\ `. . __  
#               ."" '< `.___\_<|>_/___.' >'"".  
#              | | : `- \`.;`\ _ /`;.`/ - ` : | |  
#                \ \ `-. \_ __\ /__ _/ .-` / /  
#        ======`-.____`-.___\_____/___.-`____.-'======  
#                           `=---='  
# 
#        .............................................  
#                 佛祖保佑             永无BUG 
#         佛曰:  
#                 写字楼里写字间，写字间里程序员；  
#                 程序人员写程序，又拿程序换酒钱。  
#                 酒醒只在网上坐，酒醉还来网下眠；  
#                 酒醉酒醒日复日，网上网下年复年。  
#                 但愿老死电脑间，不愿鞠躬老板前；  
#                 奔驰宝马贵者趣，公交自行程序员。  
#                 别人笑我忒疯癫，我笑自己命太贱；  
#                 不见满街漂亮妹，哪个归得程序员？
#
# 　　　┏┓　┏┓
# 　　┏┛┻━━━┛┻┓
# 　　┃　　　　  ┃ 　
# 　　┃　　　━　　 ┃
# 　　┃　＞　　 　＜┃
# 　　┃　　　　　　 ┃
# 　　┃ .. ⌒　..  ┃
# 　　┃　　   　　 ┃
# 　　┗━┓　　　┏━┛
# 　　　　┃　　　┃　Codes are far away from bugs with the animal protecting　　　　　　　
# 　　　　┃　　　┃ 神兽保佑,代码无bug
# 　　　　┃　　　┃　　　　　　　　　　　
# 　　　　┃　　　┃ 　　　　　　
# 　　　　┃　　　┃
# 　　　　┃　　　┃　　　　　　　　　　　
# 　　　　┃　　　┗━━━┓
# 　　　　┃　　　　　┣┓
# 　　　　┃　　　　┏┛
# 　　　　┗┓┓┏━┳┓┏┛
# 　　　　　┃┫┫　┃┫┫
# 　　　　　┗┻┛　┗┻┛
#
#
