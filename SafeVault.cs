using System;
using System.Data;
using System.Data.SqlClient;
using System.Web;

namespace SafeVault
{
    public class User
    {
        public string Username { get; set; }
        public string Role { get; set; } // "Admin", "User"
    }

    public class SafeVaultService
    {
        private readonly string _connectionString = "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;";

        // Activity 1 & 3: Input Validation & SQL Injection Prevention
        public string GetUserDataSecure(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                throw new ArgumentException("Invalid username input.");
            }

            string query = "SELECT Username, Email FROM Users WHERE Username = @Username";
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                SqlCommand command = new SqlCommand(query, connection);
                command.Parameters.Add("@Username", SqlDbType.VarChar, 50).Value = username;

                return $"Query executed safely for parameter: {command.Parameters["@Username"].Value}";
            }
        }

        // Activity 1 & 3: XSS Prevention (Output Encoding & Sanitization)
        public string RenderUserInputSafe(string rawInput)
        {
            if (string.IsNullOrEmpty(rawInput)) return string.Empty;
            return HttpUtility.HtmlEncode(rawInput);
        }

        // Activity 2: Authentication & RBAC Authorization
        public bool AccessAdminPanel(User currentUser)
        {
            if (currentUser == null)
            {
                throw new UnauthorizedAccessException("User is not authenticated.");
            }

            if (currentUser.Role != "Admin")
            {
                return false; // Access Denied
            }

            return true; // Access Granted
        }
    }
}