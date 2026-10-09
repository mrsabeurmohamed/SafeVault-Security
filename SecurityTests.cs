using System;
using Xunit;

namespace SafeVault.Tests
{
    public class SecurityTests
    {
        private readonly SafeVaultService _vaultService = new SafeVaultService();

        [Fact]
        public void Test_SQLi_Payload_IsHandledAsParameter()
        {
            string sqliPayload = "' OR '1'='1";
            string result = _vaultService.GetUserDataSecure(sqliPayload);
            Assert.Contains("Query executed safely for parameter: ' OR '1'='1", result);
        }

        [Fact]
        public void Test_XSS_Payload_IsEscaped()
        {
            string xssPayload = "<script>alert('XSS')</script>";
            string sanitizedOutput = _vaultService.RenderUserInputSafe(xssPayload);
            Assert.DoesNotContain("<script>", sanitizedOutput);
            Assert.Equal("&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;", sanitizedOutput);
        }

        [Fact]
        public void Test_RBAC_Denies_NonAdminUsers()
        {
            User standardUser = new User { Username = "john_doe", Role = "User" };
            bool accessGranted = _vaultService.AccessAdminPanel(standardUser);
            Assert.False(accessGranted);
        }

        [Fact]
        public void Test_RBAC_Allows_AdminUsers()
        {
            User adminUser = new User { Username = "admin_user", Role = "Admin" };
            bool accessGranted = _vaultService.AccessAdminPanel(adminUser);
            Assert.True(accessGranted);
        }
    }
}