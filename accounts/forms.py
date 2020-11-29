from datetime import timedelta

from django import forms
from django.forms import ValidationError
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from django.utils import timezone
from django.db.models import Q
from django.utils.translation import gettext_lazy as _


class UserCacheMixin:
    user_cache = None


class SignIn(UserCacheMixin, forms.Form):
    password = forms.CharField(label=_('Şifre'), strip=False, widget=forms.PasswordInput)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if settings.USE_REMEMBER_ME:
            self.fields['remember_me'] = forms.BooleanField(label=_('Beni hatırla'), required=False)

    def clean_password(self):
        password = self.cleaned_data['password']

        if not self.user_cache:
            return password

        if not self.user_cache.check_password(password):
            raise ValidationError(_('Yanlış şifre girişi yaptınız.'))

        return password


class SignInViaUsernameForm(SignIn):
    username = forms.CharField(label=_('Kullanıcı adı'))

    @property
    def field_order(self):
        if settings.USE_REMEMBER_ME:
            return ['username', 'password', 'remember_me']
        return ['username', 'password']

    def clean_username(self):
        username = self.cleaned_data['username']

        user = User.objects.filter(username=username).first()
        if not user:
            raise ValidationError(_('Böyle bir kullanıcı bulunmamaktadır.'))

        if not user.is_active:
            raise ValidationError(_('Bu hesap henüz aktif değil.'))

        self.user_cache = user

        return username


class SignInViaEmailForm(SignIn):
    email = forms.EmailField(label=_('Eposta'))

    @property
    def field_order(self):
        if settings.USE_REMEMBER_ME:
            return ['email', 'password', 'remember_me']
        return ['email', 'password']

    def clean_email(self):
        email = self.cleaned_data['email']

        user = User.objects.filter(email__iexact=email).first()
        if not user:
            raise ValidationError(_('Bu eposta üzerine kayıtlı bir kullanıcı bulunmamaktadır.'))

        if not user.is_active:
            raise ValidationError(_('Bu hesap henüz aktif değil.'))

        self.user_cache = user

        return email


class SignInViaEmailOrUsernameForm(SignIn):
    email_or_username = forms.CharField(label=_('Eposta veya kullanıcı'))

    @property
    def field_order(self):
        if settings.USE_REMEMBER_ME:
            return ['email_or_username', 'password', 'remember_me']
        return ['email_or_username', 'password']

    def clean_email_or_username(self):
        email_or_username = self.cleaned_data['email_or_username']

        user = User.objects.filter(Q(username=email_or_username) | Q(email__iexact=email_or_username)).first()
        if not user:
            raise ValidationError(_('Bu eposta veya kullanıcı adı üzerine kayıtlı bir hesap bulunmamaktadır.'))

        if not user.is_active:
            raise ValidationError(_('Bu hesap henüz aktif değil.'))

        self.user_cache = user

        return email_or_username


class SignUpForm(UserCreationForm):
    email = forms.EmailField(label=_('Eposta'), help_text=_('Gerekli. Mevcut bir eposta adresi giriniz.'))
    username = forms.CharField(label=_('Kullanıcı adı'))
    first_name = forms.CharField(label=_('Ad'), max_length=30, required=False)
    last_name = forms.CharField(label=_('Soyad'), max_length=150, required=False)
    password1 = forms.CharField(label=_('Şifre'), strip=False, widget=forms.PasswordInput, help_text=_('Şifreniz en az 8 karakter olmalı ve sadece sayılardan oluşmamalıdır.'))
    password2 = forms.CharField(label=_('Şifre onay'), strip=False, widget=forms.PasswordInput)
    
    class Meta:
        model = User
        fields = settings.SIGN_UP_FIELDS
     
    def clean_email(self):
        email = self.cleaned_data['email']

        user = User.objects.filter(email__iexact=email).exists()
        if user:
            raise ValidationError(_('Bu eposta adresini kullanamazsınız.'))

        return email

class ResendActivationCodeForm(UserCacheMixin, forms.Form):
    email_or_username = forms.CharField(label=_('Eposta veya kullanıcı adı'))

    def clean_email_or_username(self):
        email_or_username = self.cleaned_data['email_or_username']

        user = User.objects.filter(Q(username=email_or_username) | Q(email__iexact=email_or_username)).first()
        if not user:
            raise ValidationError(_('Bu eposta veya kullanıcı adı üzerine kayıtlı bir hesap bulunmamaktadır.'))

        if user.is_active:
            raise ValidationError(_('Bu hesap henüz aktif değil.'))

        activation = user.activation_set.first()
        if not activation:
            raise ValidationError(_('Aktivasyon kodu bulunamadı.'))

        now_with_shift = timezone.now() - timedelta(hours=24)
        if activation.created_at > now_with_shift:
            raise ValidationError(_('Aktivasyon kodunuz halihazırda gönderilmiştir. 24 saat içerisinde sadece bir adet kod talebinde bulunabilirsiniz.'))

        self.user_cache = user

        return email_or_username


class ResendActivationCodeViaEmailForm(UserCacheMixin, forms.Form):
    email = forms.EmailField(label=_('Eposta'))

    def clean_email(self):
        email = self.cleaned_data['email']

        user = User.objects.filter(email__iexact=email).first()
        if not user:
            raise ValidationError(_('Bu eposta üzerine kayıtlı bir kullanıcı bulunmamaktadır.'))

        if user.is_active:
            raise ValidationError(_('Bu hesap halihazırda aktif hale getirilmiş.'))

        activation = user.activation_set.first()
        if not activation:
            raise ValidationError(_('Aktivasyon kodu bulunamadı'))

        now_with_shift = timezone.now() - timedelta(hours=24)
        if activation.created_at > now_with_shift:
            raise ValidationError(_('Aktivasyon kodunuz hali hazırda gönderilmiştir. 24 saat içerisinde sadece bir adet kod talebinde bulunabilirsiniz.'))

        self.user_cache = user

        return email


class RestorePasswordForm(UserCacheMixin, forms.Form):
    email = forms.EmailField(label=_('Eposta'))

    def clean_email(self):
        email = self.cleaned_data['email']

        user = User.objects.filter(email__iexact=email).first()
        if not user:
            raise ValidationError(_('Bu eposta üzerine kayıtlı bir kullanıcı bulunmamaktadır.'))

        if not user.is_active:
            raise ValidationError(_('Bu hesap henüz aktif değil.'))

        self.user_cache = user

        return email


class RestorePasswordViaEmailOrUsernameForm(UserCacheMixin, forms.Form):
    email_or_username = forms.CharField(label=_('Eposta veya kullanıcı adı'))

    def clean_email_or_username(self):
        email_or_username = self.cleaned_data['email_or_username']

        user = User.objects.filter(Q(username=email_or_username) | Q(email__iexact=email_or_username)).first()
        if not user:
            raise ValidationError(_('Bu eposta veya kullanıcı adı üzerine kayıtlı bir hesap bulunmamaktadır.'))

        if not user.is_active:
            raise ValidationError(_('Bu hesap henüz aktif değil.'))

        self.user_cache = user

        return email_or_username


class ChangePasswordForm(UserCacheMixin, forms.Form):
    old_password = forms.CharField(label=_('Mevcut şifreniz'), strip=False, widget=forms.PasswordInput,)
    new_password1 = forms.CharField(label=_('Yeni şifre'), strip=False, widget=forms.PasswordInput, help_text=_('Şifreniz en az 8 karakter olmalı ve sadece sayılardan oluşmamalıdır.'))
    new_password2 = forms.CharField(label=_('Yeni şifre onay'), strip=False, widget=forms.PasswordInput,)

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)
    

class ChangeProfileForm(forms.Form):
    first_name = forms.CharField(label=_('Ad'), max_length=30, required=False)
    last_name = forms.CharField(label=_('Soyad'), max_length=150, required=False)


class ChangeEmailForm(forms.Form):
    email = forms.EmailField(label=_('Eposta'))

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_email(self):
        email = self.cleaned_data['email']

        if email == self.user.email:
            raise ValidationError(_('Lütfen başka bir eposta adresi giriniz.'))

        user = User.objects.filter(Q(email__iexact=email) & ~Q(id=self.user.id)).exists()
        if user:
            raise ValidationError(_('Bu eposta adresini kullanamazsınız.'))

        return email


class RemindUsernameForm(UserCacheMixin, forms.Form):
    email = forms.EmailField(label=_('Eposta'))

    def clean_email(self):
        email = self.cleaned_data['email']

        user = User.objects.filter(email__iexact=email).first()
        if not user:
            raise ValidationError(_('Bu eposta üzerine kayıtlı bir kullanıcı bulunmamaktadır.'))

        if not user.is_active:
            raise ValidationError(_('Bu hesap henüz aktif değil.'))

        self.user_cache = user

        return email
