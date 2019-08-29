using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Cybersoft.ParentOnline.Business;
using Cybersoft.Shared.Utilities;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using Resources;
using Cybersoft.ParentOnline.WebAPIs.Models.Nutrition;
using System.Data;
using System.Web.Script.Serialization;
using System.Web;
using System.Configuration;

namespace Cybersoft.ParentOnline.WebAPIs.Providers
{
    public class ApplicationOAuthProvider : OAuthAuthorizationServerProvider
    {
        private readonly string _publicClientId;
        private int intTokenValidTime
        {
            get
            {
                object objTokenValidTime = ConfigurationManager.AppSettings["PETokenValidFor"];
                return (objTokenValidTime == null) ? -10 : (objTokenValidTime.ToString() != "" ? Convert.ToInt32(objTokenValidTime.ToString()) : 15);
            }
        }

        public ApplicationOAuthProvider(string publicClientId)
        {
            if (publicClientId == null)
            {
                throw new ArgumentNullException("publicClientId");
            }

            _publicClientId = publicClientId;
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            /*
             * var userManager = context.OwinContext.GetUserManager<ApplicationUserManager>();

            ApplicationUser user = await userManager.FindAsync(context.UserName, context.Password);

            if (user == null)
            {
                context.SetError("invalid_grant", "The user name or password is incorrect.");
                return;
            }
             *
             * */

            PrivateEncryption privateEncrytion = new PrivateEncryption(ConfigHelper.GetPasswordCryptoSecretKey());
            string strUserName = context.UserName;
            string strPassword = context.Password;
            if (context.Scope[0].ToLower() == "autologin")
            {
                string decryptedPODetails = privateEncrytion.Decrypt(context.Password.Replace("~", "/").Replace("`", "="));

                string[] strAuthDetails = decryptedPODetails.Split(new string[] { "POKeyValue" }, StringSplitOptions.None);
                string strLoginUserName = strAuthDetails[0].ToString();
                string strKeyValue = strAuthDetails[1].ToString();

                string decryptTimeStamp = strKeyValue;
                bool expired = Math.Abs((DateTime.UtcNow - new DateTime(Convert.ToInt64(decryptTimeStamp))).TotalMinutes) < intTokenValidTime;

                if (!expired)
                {
                    context.SetError("invalid_grant", "Token expired. Please try again.");
                    return;
                }

                strUserName = strPassword = strAuthDetails[0].ToString();
            }
            int? userId = null;
            int? districtId = null;
            bool isFirstTimeLogin = false;
            //string password = context.Password.Substring(0, Math.Min(context.Password.Length, 12));
            string encyptedPassword = context.Scope[0].ToLower() == "supportlogin" ? strPassword : privateEncrytion.Encrypt(strPassword);
            byte? isValid = UserSecurity.AuthenticateUser(strUserName, encyptedPassword, ref userId, ref districtId);

            if (userId == 0)
            {
                context.SetError("invalid_grant", "The user name or password is incorrect.");
                return;
            }

            DataTable dtsocialShare = null;
            SharingModel SocialShare = new SharingModel();

            if (districtId != null)
            {
                dtsocialShare = UserSecurity.GetsocialShare(districtId.Value);

                foreach (DataRow drShare in dtsocialShare.Rows)
                {
                    SocialShare.FaceBookSharing = drShare.Field<bool>("Facebook Share");
                    SocialShare.InstagramSharing = drShare.Field<bool>("Instagram Share");
                    SocialShare.TwitterSharing = drShare.Field<bool>("Twitter Share");
                }
            }

            UserProfile ud = UserSecurity.RetrieveUserDetail(userId);
            District isd = District.GetDistrict(districtId);

            if (ud.LastLoginDate == Convert.ToDateTime("1/1/1900 12:00:00 AM") || ud.LastLoginDate == DateTime.MinValue || ud.LastLoginDate == null)
            {
                isFirstTimeLogin = true;
            }
            else
            {
                isFirstTimeLogin = false;
            }

            switch (isValid)
            {
                case 0: //User successfully logged in
                    /*
                     * if (UrlHelper.CanUserLoginToRequestedURL(districtId))
                    {
                        Security.Login(userId);
                        PageHelper.TransferUserToDefaultPage();
                    }
                    else
                    {
                        PrivateEncryption encryption = new PrivateEncryption(ConfigHelper.GetPasswordCryptoSecretKey());
                        PageHelper.TransferToPage(UrlHelper.GetOperationUrl("LOGIN", districtId) + "?cd="
                                                  + Server.UrlEncode(encryption.Encrypt(string.Format(DateTime.Now + "|" + userNameTextBox.Text + "|" + encryption.Encrypt(userPasswordTextBox.Text.Trim())))));
                    }
                     */
                    UserSecurity.UpdateLastLoginDate(userId, DateTime.Now);
                    //Cannot use Activity Logging because it relys on Session.     
                    //ActivityLogging.AddActivity(ActivityKey.Login);
                    //ActivityLogging.UpdateActivity(true, "");
                    break;
                case 1:
                    //User does not exist
                    context.SetError("invalid_grant", MessagesList.ERR_LOGIN_NOTREGISTER);
                    return;
                case 2:
                    //Password failed
                    context.SetError("invalid_grant", MessagesList.ERR_LOGIN_PASSWORDFAILED);
                    return;
                case 3:
                    //Failed login attempts exceeded
                    string error = string.Format(MessagesList.ERR_LOGIN_PASSWORDFAILEDATTEMPTSMORE, Setting.GetSettingValue(SettingMasterKey.AllowableFailedLoginAttempts, districtId), Setting.GetSettingValue(SettingMasterKey.AllowableReLoginDurationAfterexceedingTheAllowableFailedLoginAttempts, districtId));
                    context.SetError("invalid_grant", error);
                    return;
                case 4:
                    //User disabled
                    context.SetError("invalid_grant", MessagesList.ERR_LOGIN_PASSWORDDISABLED);
                    return;
                case 5:
                    //User registered but not activated
                    context.SetError("invalid_grant", MessagesList.ERR_LOGIN_REGISTERNOTACTIVATED);
                    return;
            }

            double? studentBalance = null;
            studentBalance = Student.GetStudentBalance((int)userId);
            //if (!ud.IsParent)
            //{
            //    context.SetError("invalid_grant", "Only parents are allowed to login");
            //    return;
            //}

            ClaimsIdentity oAuthIdentity = new ClaimsIdentity(OAuthDefaults.AuthenticationType);
            ClaimsIdentity cookiesIdentity = new ClaimsIdentity(OAuthDefaults.AuthenticationType);
            if (ud.AccessId == 3 || ud.AccessId == 4)
                oAuthIdentity.AddClaim(new Claim(ClaimTypes.Role, "Admin"));
            else
                oAuthIdentity.AddClaim(new Claim(ClaimTypes.Role, "User"));

            Claim claim = new Claim("UserId", userId.ToString());
            oAuthIdentity.AddClaim(claim);
            cookiesIdentity.AddClaim(claim);

            if (districtId == null)
                districtId = 0;
            claim = new Claim("DistrictId", districtId.ToString());
            oAuthIdentity.AddClaim(claim);
            cookiesIdentity.AddClaim(claim);

            if (isd != null)
            {
                claim = new Claim("DistrictName", isd.DistrictName);
                oAuthIdentity.AddClaim(claim);
                cookiesIdentity.AddClaim(claim);
            }

            claim = new Claim("UserName", strUserName);
            oAuthIdentity.AddClaim(claim);
            cookiesIdentity.AddClaim(claim);

            claim = new Claim("AccessLevel", ud.AccessId.ToString());
            oAuthIdentity.AddClaim(claim);
            cookiesIdentity.AddClaim(claim);

            string cd = privateEncrytion.Encrypt(DateTime.Now.ToString() + "|" + strUserName + "|" + encyptedPassword);
            string redirectURL = Setting.GetDefaultValue(22);
            string APPEB = Setting.GetSettingValue(SettingMasterKey.EligibilityBenefitsForAPP, districtId.Value);
            string WEBAB = Setting.GetSettingValue(SettingMasterKey.EligibilityBenefitsForWEB, districtId.Value);
            string showPic = Setting.GetSettingValue(SettingMasterKey.ShowPicturesFromPrimeroEdge, districtId.Value);
            long TimeStamp = DateTime.UtcNow.Ticks;

            //Upon login, display a message to confirm email address for users that have not logged in recently i.e 90Days.
            double LoginDiffDays = 0;
            bool LoginDiffrence = false;
            if (context.Scope[0].ToLower() != "autologin")
            {
                if (ud.LastLoginDate.Value.ToShortDateString() == "1/1/1900")
                    LoginDiffrence = false;
                else
                    LoginDiffDays = (DateTime.Now - ud.LastLoginDate.Value).TotalDays;

                if (LoginDiffDays >= 90)
                    LoginDiffrence = true;
            }

            string encyptedTimeStamp = privateEncrytion.Encrypt(TimeStamp.ToString());

            AuthenticationProperties properties = CreateProperties(strUserName);
            properties.Dictionary.Add("FirstName", ud.ContactInformation.FirstName);
            properties.Dictionary.Add("DistrictName", isd == null ? "" : isd.DistrictName);
            properties.Dictionary.Add("Status", isd == null ? "" : isd.Status.ToString());
            properties.Dictionary.Add("AccessLevel", ud.AccessId.ToString());
            properties.Dictionary.Add("RedirectURL", redirectURL);
            properties.Dictionary.Add("StudentBalance", studentBalance.ToString());
            properties.Dictionary.Add("FaceBookSharing", SocialShare.FaceBookSharing.ToString());
            properties.Dictionary.Add("InstagramSharing", SocialShare.InstagramSharing.ToString());
            properties.Dictionary.Add("TwitterSharing", SocialShare.TwitterSharing.ToString());
            properties.Dictionary.Add("ISDId", districtId.ToString());
            properties.Dictionary.Add("APPEB", APPEB);
            properties.Dictionary.Add("WEBEB", WEBAB);
            properties.Dictionary.Add("OnlineAppsToken", encyptedTimeStamp);
            properties.Dictionary.Add("UserId", userId.ToString());
            properties.Dictionary.Add("LoginDiffrence", LoginDiffrence.ToString());
            properties.Dictionary.Add("Email", ud.ContactInformation.Email);
            properties.Dictionary.Add("Verified", ud.Verified?.ToString());
            properties.Dictionary.Add("ShowPicture", showPic);
            properties.Dictionary.Add("IsFirstTimeLogin", Convert.ToString(isFirstTimeLogin));
            properties.Dictionary.Add("UserIP", Helper.GetIP());
            properties.Dictionary.Add("UserTypeId", Convert.ToString(ud.UserTypeId));

            if (districtId != 0)
            {
                properties.Dictionary.Add("OnlineAppURL", Helper.GetOnlineAppUrl(districtId.Value));
            }

            //properties.Dictionary.Add("SocialShare", (new JavaScriptSerializer().Serialize(SocialShare)).Replace("\"", ""));
            AuthenticationTicket ticket = new AuthenticationTicket(oAuthIdentity, properties);
            context.Validated(ticket);
            context.Request.Context.Authentication.SignIn(cookiesIdentity);
        }

        public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            foreach (KeyValuePair<string, string> property in context.Properties.Dictionary)
            {
                context.AdditionalResponseParameters.Add(property.Key, property.Value);
            }

            return Task.FromResult<object>(null);
        }

        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            // Resource owner password credentials does not provide a client ID.
            if (context.ClientId == null)
            {
                context.Validated();
            }

            return Task.FromResult<object>(null);
        }

        public override Task ValidateClientRedirectUri(OAuthValidateClientRedirectUriContext context)
        {
            if (context.ClientId == _publicClientId)
            {
                Uri expectedRootUri = new Uri(context.Request.Uri, "/");

                if (expectedRootUri.AbsoluteUri == context.RedirectUri)
                {
                    context.Validated();
                }
            }

            return Task.FromResult<object>(null);
        }

        public static AuthenticationProperties CreateProperties(string userName)
        {
            IDictionary<string, string> data = new Dictionary<string, string>
            {
                { "userName", userName }
            };
            return new AuthenticationProperties(data);
        }
    }
}