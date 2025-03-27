using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace ZeroTrustNavigator
{
    public class ZeroTrustNavigator
    {
        private readonly ILogger<ZeroTrustNavigator> _logger;
        private readonly Dictionary<string, UserContext> _userContexts;
        private readonly Dictionary<string, ResourcePolicy> _resourcePolicies;
        private readonly Dictionary<string, DeviceContext> _deviceContexts;
        private readonly List<NetworkSegment> _networkSegments;
        
        public ZeroTrustNavigator(ILogger<ZeroTrustNavigator> logger)
        {
            _logger = logger;
            _userContexts = new Dictionary<string, UserContext>();
            _resourcePolicies = new Dictionary<string, ResourcePolicy>();
            _deviceContexts = new Dictionary<string, DeviceContext>();
            _networkSegments = new List<NetworkSegment>();
        }
        
        public async Task<AccessDecision> EvaluateAccessRequest(AccessRequest request)
        {
            _logger.LogInformation($"Evaluating access request for User: {request.UserId} on Resource: {request.ResourceId}");
            
            try
            {
                if (!await ValidateAuthentication(request.UserId, request.AuthToken))
                    return DeniedDecision("Authentication failed", 1.0, new List<string> { "reauthenticate" });
                
                var deviceContext = await GetDeviceContext(request.DeviceId);
                if (deviceContext.RiskScore > 0.7)
                    return DeniedDecision("Device risk too high", deviceContext.RiskScore, deviceContext.RequiredActions);
                
                var networkContext = await EvaluateNetworkContext(request.NetworkInfo);
                if (networkContext.RiskScore > 0.7)
                    return DeniedDecision("Network risk too high", networkContext.RiskScore, new List<string> { "use_vpn" });
                
                if (!_resourcePolicies.TryGetValue(request.ResourceId, out var policy))
                    return DeniedDecision("Resource policy not found", 0.5, new List<string>());
                
                var userContext = _userContexts[request.UserId];
                var accessLevel = DetermineAccessLevel(userContext, policy, request.RequestedPermissions);
                var overallRiskScore = RiskEvaluator.CalculateOverallRisk(userContext.RiskScore, deviceContext.RiskScore, networkContext.RiskScore, policy.Sensitivity);
                
                bool allowed = accessLevel != AccessLevel.Denied && overallRiskScore < policy.MaxAcceptableRisk;
                var requiredActions = new List<string>();
                if (allowed && overallRiskScore > policy.EnhancedControlsThreshold)
                {
                    requiredActions.Add("mfa_verification");
                    requiredActions.Add("session_recording");
                }
                
                _logger.LogInformation($"Access decision for {request.UserId} to {request.ResourceId}: {(allowed ? "Allowed" : "Denied")}");
                
                return new AccessDecision
                {
                    Allowed = allowed,
                    Reason = allowed ? "Access granted with controls" : "Risk threshold exceeded",
                    RiskScore = overallRiskScore,
                    RequiredActions = requiredActions,
                    GrantedPermissions = allowed ? DetermineGrantedPermissions(accessLevel, request.RequestedPermissions) : new List<string>(),
                    SessionTimeoutMinutes = DetermineSessionTimeout(overallRiskScore)
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error evaluating access request");
                return DeniedDecision("Internal error", 1.0, new List<string> { "contact_admin" });
            }
        }
        
        private async Task<bool> ValidateAuthentication(string userId, string authToken)
        {
            return !string.IsNullOrEmpty(authToken) && _userContexts.ContainsKey(userId) && VerifyToken(authToken, userId);
        }
        
        private bool VerifyToken(string token, string userId)
        {
            using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes("secure_key")))
            {
                var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(userId));
                return Convert.ToBase64String(computedHash) == token;
            }
        }
        
        private static AccessDecision DeniedDecision(string reason, double riskScore, List<string> requiredActions)
        {
            return new AccessDecision
            {
                Allowed = false,
                Reason = reason,
                RiskScore = riskScore,
                RequiredActions = requiredActions
            };
        }
    }
}
