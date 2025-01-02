#include <iostream>
#include <fstream>
#include <map>
#include <vector>
#include <sstream>
#include <string>
#include <algorithm>
#include <iomanip>
#include <ctime>
#include <numeric>
#include <direct.h>
#include <set>
#include <stdexcept>
#include <thread>
#include <chrono>
#include <iterator>
#include <regex>
#include <random>
#include <cmath>
#include <queue>
#include <stack>
#include <unordered_map>
#include <functional>
#include <memory>
#include <future>
#include <mutex>

using namespace std;

// Define Constants
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "admin123"
#define MIN_PASSWORD_LENGTH 6
#define LOG_FILE "activity_log.txt"
#define FEEDBACK_FILE "feedback_data.txt"
#define CSV_FILE "feedback_export.csv"
#define USER_FILE "user_data.txt"
#define DESTINATION_FILE "destination_data.txt"
#define RECOMMENDATION_FILE "recommendation_data.txt"
#define MAX_LOGIN_ATTEMPTS 3
#define SESSION_TIMEOUT 1800 // 30 minutes in seconds

// Forward declarations
class UserManager;
class FeedbackManager;
class DestinationManager;
class RecommendationSystem;

// Utility Class for Repeated Functionalities
class Utility {
public:
    static void logActivity(const string &activity) {
        static mutex logMutex;
        lock_guard<mutex> lock(logMutex);

        ofstream logFile(LOG_FILE, ios::app);
        if (!logFile) {
            cerr << "Error: Unable to open log file!" << endl;
            return;
        }

        time_t now = time(0);
        string timestamp = ctime(&now);
        timestamp.pop_back();
        logFile << "[" << timestamp << "] " << activity << endl;
        logFile.close();
    }

    static bool isValidRating(int rating) {
        return rating >= 1 && rating <= 5;
    }

    static bool isValidUsername(const string &username) {
        return !username.empty() && username.find_first_not_of(" \t") != string::npos;
    }

    static bool isValidPassword(const string &password) {
        if (password.length() < MIN_PASSWORD_LENGTH) return false;
        bool hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
        for (char c : password) {
            if (isupper(c)) hasUpper = true;
            else if (islower(c)) hasLower = true;
            else if (isdigit(c)) hasDigit = true;
            else hasSpecial = true;
        }
        return hasUpper && hasLower && hasDigit && hasSpecial;
    }

    static bool isValidEmail(const string &email) {
        regex emailPattern(R"((\w+)(\.\w+)*@(\w+\.)+[a-zA-Z]{2,})");
        return regex_match(email, emailPattern);
    }

    static void printSeparator() {
        cout << string(80, '*') << endl;
    }

    static void pause() {
        cout << "Press Enter to continue..." << endl;
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
    }

    static void exportToCSV(const vector<string> &feedbackList) {
        ofstream file(CSV_FILE);
        if (!file) {
            cerr << "Error: Unable to create CSV file!" << endl;
            return;
        }

        file << "Username,Destination,Rating,Comment,Timestamp\n";
        for (const auto &feedback : feedbackList) {
            file << feedback << endl;
        }
        file.close();
        logActivity("Feedback exported to CSV.");
        cout << "Feedback successfully exported to '" << CSV_FILE << "'!" << endl;
    }

    static void ensureDirectoryExists(const string &dirName) {
        if (_mkdir(dirName.c_str()) != 0 && errno != EEXIST) {
            cerr << "Error: Unable to create directory!" << endl;
        }
    }

    static string getCurrentTimestamp() {
        time_t now = time(0);
        string timestamp = ctime(&now);
        timestamp.pop_back();
        return timestamp;
    }

    static void showErrorMessage(const string &message) {
        cout << "\033[1;31mError: " << message << "\033[0m" << endl;
    }

    static void showSuccessMessage(const string &message) {
        cout << "\033[1;32mSuccess: " << message << "\033[0m" << endl;
    }

    static void showInfoMessage(const string &message) {
        cout << "\033[1;34mInfo: " << message << "\033[0m" << endl;
    }

    static void clearScreen() {
        #ifdef _WIN32
            system("cls");
        #else
            system("clear");
        #endif
    }

    static string hashPassword(const string &password) {
        // This is a simple hash function for demonstration purposes
        // In a real-world application, use a secure hashing algorithm like bcrypt
        hash<string> hasher;
        return to_string(hasher(password));
    }

    static string generateToken() {
        static random_device rd;
        static mt19937 gen(rd());
        static uniform_int_distribution<> dis(0, 15);
        static const char *hex = "0123456789abcdef";
        string token;
        for (int i = 0; i < 32; ++i) {
            token += hex[dis(gen)];
        }
        return token;
    }

    static bool isTokenExpired(const string &timestamp, int timeout) {
        time_t now = time(0);
        time_t tokenTime = stoi(timestamp);
        return difftime(now, tokenTime) > timeout;
    }
};

// User Class
class User {
private:
    string username;
    string passwordHash;
    string email;
    string profileInfo;
    bool isAdmin;
    bool isModerator;
    string lastLogin;
    vector<string> loginHistory;
    int loginAttempts;
    string authToken;
    string tokenTimestamp;

public:
    User(const string &username, const string &password, const string &email, bool isAdmin = false, bool isModerator = false)
        : username(username), passwordHash(Utility::hashPassword(password)), email(email), isAdmin(isAdmin), isModerator(isModerator), loginAttempts(0) {}

    bool verifyPassword(const string &password) const {
        return passwordHash == Utility::hashPassword(password);
    }

    void setPassword(const string &newPassword) {
        passwordHash = Utility::hashPassword(newPassword);
    }

    void setEmail(const string &newEmail) {
        email = newEmail;
    }

    void setProfileInfo(const string &info) {
        profileInfo = info;
    }

    void setModerator(bool status) {
        isModerator = status;
    }

    void recordLogin() {
        lastLogin = Utility::getCurrentTimestamp();
        loginHistory.push_back(lastLogin);
        if (loginHistory.size() > 10) {
            loginHistory.erase(loginHistory.begin());
        }
    }

    void incrementLoginAttempts() {
        loginAttempts++;
    }

    void resetLoginAttempts() {
        loginAttempts = 0;
    }

    void setAuthToken(const string &token) {
        authToken = token;
        tokenTimestamp = to_string(time(0));
    }

    bool isTokenValid(int timeout) const {
        return !Utility::isTokenExpired(tokenTimestamp, timeout);
    }

    string getUsername() const { return username; }
    string getEmail() const { return email; }
    string getProfileInfo() const { return profileInfo; }
    bool isAdminUser() const { return isAdmin; }
    bool isModeratorUser() const { return isModerator; }
    string getLastLogin() const { return lastLogin; }
    const vector<string>& getLoginHistory() const { return loginHistory; }
    int getLoginAttempts() const { return loginAttempts; }
    string getAuthToken() const { return authToken; }
};

// UserManager Class for Managing Users
class UserManager {
private:
    unordered_map<string, shared_ptr<User>> users;
    mutex userMutex;

public:
    UserManager() {
        loadUsers();
    }

    void loadUsers() {
        ifstream file(USER_FILE);
        if (!file) return;

        string line;
        while (getline(file, line)) {
            stringstream ss(line);
            string username, passwordHash, email, profileInfo, isAdmin, isModerator, lastLogin;
            getline(ss, username, ',');
            getline(ss, passwordHash, ',');
            getline(ss, email, ',');
            getline(ss, profileInfo, ',');
            getline(ss, isAdmin, ',');
            getline(ss, isModerator, ',');
            getline(ss, lastLogin);

            shared_ptr<User> user = make_shared<User>(username, "", email, isAdmin == "1", isModerator == "1");
            user->setProfileInfo(profileInfo);
            users[username] = user;
        }
        file.close();
    }

    void saveUsers() {
        ofstream file(USER_FILE);
        if (!file) {
            Utility::showErrorMessage("Unable to save user data!");
            return;
        }
        for (const auto &pair : users) {
            const auto &user = pair.second;
            file << user->getUsername() << ","
                 << user->getEmail() << ","
                 << user->getProfileInfo() << ","
                 << (user->isAdminUser() ? "1" : "0") << ","
                 << (user->isModeratorUser() ? "1" : "0") << ","
                 << user->getLastLogin() << endl;
        }
        file.close();
    }

    bool registerUser(const string &username, const string &password, const string &email) {
        lock_guard<mutex> lock(userMutex);

        if (!Utility::isValidUsername(username)) {
            Utility::showErrorMessage("Invalid username!");
            return false;
        }

        if (!Utility::isValidPassword(password)) {
            Utility::showErrorMessage("Invalid password! Password must be at least 6 characters long and contain uppercase, lowercase, digit, and special character.");
            return false;
        }

        if (!Utility::isValidEmail(email)) {
            Utility::showErrorMessage("Invalid email format!");
            return false;
        }

        if (users.count(username)) {
            Utility::showErrorMessage("Username already exists!");
            return false;
        }

        users[username] = make_shared<User>(username, password, email);
        Utility::logActivity("User registered: " + username);
        Utility::showSuccessMessage("User registered successfully!");
        saveUsers();
        return true;
    }

    shared_ptr<User> loginUser(const string &username, const string &password) {
        lock_guard<mutex> lock(userMutex);

        auto it = users.find(username);
        if (it == users.end()) {
            Utility::showErrorMessage("User not found.");
            return nullptr;
        }

        shared_ptr<User> user = it->second;
        if (user->getLoginAttempts() >= MAX_LOGIN_ATTEMPTS) {
            Utility::showErrorMessage("Account locked due to too many failed attempts. Please contact an administrator.");
            return nullptr;
        }

        if (!user->verifyPassword(password)) {
            user->incrementLoginAttempts();
            Utility::showErrorMessage("Invalid password.");
            return nullptr;
        }

        user->resetLoginAttempts();
        user->recordLogin();
        string token = Utility::generateToken();
        user->setAuthToken(token);
        Utility::logActivity("User logged in: " + username);
        Utility::showSuccessMessage("Login successful! Welcome, " + username + "!");
        saveUsers();
        return user;
    }

    bool loginAdmin(const string &username, const string &password) {
        lock_guard<mutex> lock(userMutex);

        auto it = users.find(username);
        if (it == users.end() || !it->second->isAdminUser()) {
            Utility::showErrorMessage("Invalid admin credentials.");
            return false;
        }

        shared_ptr<User> admin = it->second;
        if (!admin->verifyPassword(password)) {
            Utility::showErrorMessage("Invalid admin credentials.");
            return false;
        }

        admin->recordLogin();
        Utility::logActivity("Admin logged in: " + username);
        Utility::showSuccessMessage("Admin login successful! Welcome, " + username + "!");
        saveUsers();
        return true;
    }

    bool addModerator(const string &username) {
        lock_guard<mutex> lock(userMutex);

        auto it = users.find(username);
        if (it == users.end()) {
            Utility::showErrorMessage("User does not exist.");
            return false;
        }

        it->second->setModerator(true);
        Utility::logActivity("Moderator added: " + username);
        Utility::showSuccessMessage(username + " is now a moderator.");
        saveUsers();
        return true;
    }

    bool removeModerator(const string &username) {
        lock_guard<mutex> lock(userMutex);

        auto it = users.find(username);
        if (it == users.end() || !it->second->isModeratorUser()) {
            Utility::showErrorMessage("User is not a moderator.");
            return false;
        }

        it->second->setModerator(false);
        Utility::logActivity("Moderator removed: " + username);
        Utility::showSuccessMessage(username + " is no longer a moderator.");
        saveUsers();
        return true;
    }

    bool updateUserProfile(const string &username, const string &profileInfo) {
        lock_guard<mutex> lock(userMutex);

        auto it = users.find(username);
        if (it == users.end()) {
            Utility::showErrorMessage("User does not exist.");
            return false;
        }

        it->second->setProfileInfo(profileInfo);
        Utility::logActivity("Profile updated for user: " + username);
        Utility::showSuccessMessage("Profile updated successfully!");
        saveUsers();
        return true;
    }

    bool changePassword(const string &username, const string &oldPassword, const string &newPassword) {
        lock_guard<mutex> lock(userMutex);

        auto it = users.find(username);
        if (it == users.end()) {
            Utility::showErrorMessage("User does not exist.");
            return false;
        }

        shared_ptr<User> user = it->second;
        if (!user->verifyPassword(oldPassword)) {
            Utility::showErrorMessage("Incorrect old password.");
            return false;
        }

        if (!Utility::isValidPassword(newPassword)) {
            Utility::showErrorMessage("Invalid new password! Password must be at least 6 characters long and contain uppercase, lowercase, digit, and special character.");
            return false;
        }

        user->setPassword(newPassword);
        Utility::logActivity("Password changed for user: " + username);
        Utility::showSuccessMessage("Password changed successfully.");
        saveUsers();
        return true;
    }

    bool removeUser(const string &username) {
        lock_guard<mutex> lock(userMutex);

        auto it = users.find(username);
        if (it == users.end()) {
            Utility::showErrorMessage("User does not exist.");
            return false;
        }

        users.erase(it);
        Utility::logActivity("User removed: " + username);
        Utility::showSuccessMessage("User removed successfully.");
        saveUsers();
        return true;
    }

    void listUsers() {
        lock_guard<mutex> lock(userMutex);

        if (users.empty()) {
            Utility::showInfoMessage("No users found.");
            return;
        }

        cout << "List of Users:\n";
        for (const auto &pair : users) {
            const auto &user = pair.second;
            cout << "Username: " << user->getUsername()
                 << ", Email: " << user->getEmail()
                 << ", Admin: " << (user->isAdminUser() ? "Yes" : "No")
                 << ", Moderator: " << (user->isModeratorUser() ? "Yes" : "No")
                 << ", Last Login: " << user->getLastLogin() << endl;
        }
    }

    void searchUser(const string &username) {
        lock_guard<mutex> lock(userMutex);

        auto it = users.find(username);
        if (it == users.end()) {
            Utility::showErrorMessage("User not found.");
            return;
        }

        const auto &user = it->second;
        cout << "User found:\n"
             << "Username: " << user->getUsername() << "\n"
             << "Email: " << user->getEmail() << "\n"
             << "Admin: " << (user->isAdminUser() ? "Yes" : "No") << "\n"
             << "Moderator: " << (user->isModeratorUser() ? "Yes" : "No") << "\n"
             << "Last Login: " << user->getLastLogin() << "\n"
             << "Profile Info: " << user->getProfileInfo() << endl;
    }

    bool isValidSession(const string &username, const string &token) {
        lock_guard<mutex> lock(userMutex);

        auto it = users.find(username);
        if (it == users.end()) return false;

        shared_ptr<User> user = it->second;
        return user->getAuthToken() == token && user->isTokenValid(SESSION_TIMEOUT);
    }
};

// Feedback Class
class Feedback {
private:
    string username;
    string destination;
    int rating;
    string comment;
    string timestamp;
    vector<string> photos;
    vector<string> videos;
    map<string, int> helpfulVotes;
    bool isVerified;

public:
    Feedback(const string &username, const string &destination, int rating, const string &comment)
        : username(username), destination(destination), rating(rating), comment(comment),
          timestamp(Utility::getCurrentTimestamp()), isVerified(false) {}

    void addPhoto(const string &photoPath) {
        photos.push_back(photoPath);
    }

    void addVideo(const string &videoPath) {
        videos.push_back(videoPath);
    }

    void addHelpfulVote(const string &voter) {
        helpfulVotes[voter]++;
    }

    void removeHelpfulVote(const string &voter) {
        auto it = helpfulVotes.find(voter);
        if (it != helpfulVotes.end()) {
            if (--it->second == 0) {
                helpfulVotes.erase(it);
            }
        }
    }

    void setVerified(bool status) {
        isVerified = status;
    }

    string getUsername() const { return username; }
    string getDestination() const { return destination; }
    int getRating() const { return rating; }
    string getComment() const { return comment; }
    string getTimestamp() const { return timestamp; }
    const vector<string>& getPhotos() const { return photos; }
    const vector<string>& getVideos() const { return videos; }
    int getTotalHelpfulVotes() const {
        return accumulate(helpfulVotes.begin(), helpfulVotes.end(), 0,
                          [](int sum, const auto &p) { return sum + p.second; });
    }
    bool getVerificationStatus() const { return isVerified; }
};

// FeedbackManager Class for Managing Feedback
class FeedbackManager {
private:
    vector<shared_ptr<Feedback>> feedbackList;
    mutex feedbackMutex;

public:
    FeedbackManager() {
        loadFeedback();
    }

    void loadFeedback() {
        ifstream file(FEEDBACK_FILE);
        if (!file) return;

        string line;
        while (getline(file, line)) {
            stringstream ss(line);
            string username, destination, ratingStr, comment, timestamp;
            getline(ss, username, ',');
            getline(ss, destination, ',');
            getline(ss, ratingStr, ',');
            getline(ss, comment, ',');
            getline(ss, timestamp);

            int rating = stoi(ratingStr);
            auto feedback = make_shared<Feedback>(username, destination, rating, comment);
            feedbackList.push_back(feedback);
        }
        file.close();
    }

    void saveFeedback() {
        ofstream file(FEEDBACK_FILE);
        if (!file) {
            Utility::showErrorMessage("Unable to save feedback!");
            return;
        }
        for (const auto &fb : feedbackList) {
            file << fb->getUsername() << ","
                 << fb->getDestination() << ","
                 << fb->getRating() << ","
                 << fb->getComment() << ","
                 << fb->getTimestamp() << endl;
        }
        file.close();
    }

    bool submitFeedback(const string &username, const string &destination, int rating, const string &comment) {
        lock_guard<mutex> lock(feedbackMutex);

        if (!Utility::isValidRating(rating)) {
            Utility::showErrorMessage("Rating must be between 1 and 5.");
            return false;
        }

        auto feedback = make_shared<Feedback>(username, destination, rating, comment);
        feedbackList.push_back(feedback);
        Utility::logActivity("Feedback submitted by: " + username);
        Utility::showSuccessMessage("Feedback submitted successfully!");
        saveFeedback();
        return true;
    }

    void viewFeedback(const string &destination) {
        lock_guard<mutex> lock(feedbackMutex);

        bool found = false;
        for (const auto &fb : feedbackList) {
            if (fb->getDestination() == destination) {
                cout << "User: " << fb->getUsername()
                     << ", Rating: " << fb->getRating()
                     << ", Comment: " << fb->getComment()
                     << ", Timestamp: " << fb->getTimestamp()
                     << ", Helpful Votes: " << fb->getTotalHelpfulVotes()
                     << ", Verified: " << (fb->getVerificationStatus() ? "Yes" : "No") << endl;
                found = true;
            }
        }
        if (!found) {
            Utility::showErrorMessage("No feedback found for " + destination);
        }
    }

    bool deleteFeedbackByModerator(const string &destination, const string &username) {
        lock_guard<mutex> lock(feedbackMutex);

        auto it = remove_if(feedbackList.begin(), feedbackList.end(),
            [&](const shared_ptr<Feedback> &fb) {
                return fb->getDestination() == destination && fb->getUsername() == username;
            });

        if (it != feedbackList.end()) {
            feedbackList.erase(it, feedbackList.end());
            Utility::logActivity("Feedback deleted for destination: " + destination + " by moderator.");
            Utility::showSuccessMessage("Feedback deleted successfully.");
            saveFeedback();
            return true;
        } else {
            Utility::showErrorMessage("No feedback found for deletion.");
            return false;
        }
    }

    void listFeedbacks() {
        lock_guard<mutex> lock(feedbackMutex);

        if (feedbackList.empty()) {
            Utility::showInfoMessage("No feedback available.");
            return;
        }

        cout << "Feedback List:\n";
        for (const auto &fb : feedbackList) {
            cout << "Username: " << fb->getUsername()
                 << ", Destination: " << fb->getDestination()
                 << ", Rating: " << fb->getRating()
                 << ", Comment: " << fb->getComment()
                 << ", Timestamp: " << fb->getTimestamp()
                 << ", Helpful Votes: " << fb->getTotalHelpfulVotes()
                 << ", Verified: " << (fb->getVerificationStatus() ? "Yes" : "No") << endl;
        }
    }

    bool addHelpfulVote(const string &destination, const string &username, const string &voter) {
        lock_guard<mutex> lock(feedbackMutex);

        auto it = find_if(feedbackList.begin(), feedbackList.end(),
            [&](const shared_ptr<Feedback> &fb) {
                return fb->getDestination() == destination && fb->getUsername() == username;
            });

        if (it != feedbackList.end()) {
            (*it)->addHelpfulVote(voter);
            Utility::showSuccessMessage("Helpful vote added successfully.");
            saveFeedback();
            return true;
        } else {
            Utility::showErrorMessage("Feedback not found.");
            return false;
        }
    }

    bool removeHelpfulVote(const string &destination, const string &username, const string &voter) {
        lock_guard<mutex> lock(feedbackMutex);

        auto it = find_if(feedbackList.begin(), feedbackList.end(),
            [&](const shared_ptr<Feedback> &fb) {
                return fb->getDestination() == destination && fb->getUsername() == username;
            });

        if (it != feedbackList.end()) {
            (*it)->removeHelpfulVote(voter);
            Utility::showSuccessMessage("Helpful vote removed successfully.");
            saveFeedback();
            return true;
        } else {
            Utility::showErrorMessage("Feedback not found.");
            return false;
        }
    }

    bool verifyFeedback(const string &destination, const string &username) {
        lock_guard<mutex> lock(feedbackMutex);

        auto it = find_if(feedbackList.begin(), feedbackList.end(),
            [&](const shared_ptr<Feedback> &fb) {
                return fb->getDestination() == destination && fb->getUsername() == username;
            });

        if (it != feedbackList.end()) {
            (*it)->setVerified(true);
            Utility::showSuccessMessage("Feedback verified successfully.");
            saveFeedback();
            return true;
        } else {
            Utility::showErrorMessage("Feedback not found.");
            return false;
        }
    }

    vector<shared_ptr<Feedback>> getFeedbackForDestination(const string &destination) {
        lock_guard<mutex> lock(feedbackMutex);

        vector<shared_ptr<Feedback>> result;
        copy_if(feedbackList.begin(), feedbackList.end(), back_inserter(result),
            [&](const shared_ptr<Feedback> &fb) {
                return fb->getDestination() == destination;
            });
        return result;
    }
};

// Destination Class
class Destination {
private:
    string name;
    string description;
    vector<string> categories;
    map<string, double> prices;
    vector<string> photos;
    vector<string> videos;
    double averageRating;
    int totalRatings;
    bool isActive;

public:
    Destination(const string &name, const string &description)
        : name(name), description(description), averageRating(0), totalRatings(0), isActive(true) {}

    void addCategory(const string &category) {
        categories.push_back(category);
    }

    void setPrice(const string &priceType, double amount) {
        prices[priceType] = amount;
    }

    void addPhoto(const string &photoPath) {
        photos.push_back(photoPath);
    }

    void addVideo(const string &videoPath) {
        videos.push_back(videoPath);
    }

    void updateRating(int newRating) {
        averageRating = (averageRating * totalRatings + newRating) / (totalRatings + 1);
        totalRatings++;
    }

    void setActive(bool status) {
        isActive = status;
    }

    string getName() const { return name; }
    string getDescription() const { return description; }
    const vector<string>& getCategories() const { return categories; }
    const map<string, double>& getPrices() const { return prices; }
    const vector<string>& getPhotos() const { return photos; }
    const vector<string>& getVideos() const { return videos; }
    double getAverageRating() const { return averageRating; }
    int getTotalRatings() const { return totalRatings; }
    bool getActiveStatus() const { return isActive; }
};

// DestinationManager Class for Managing Destinations
class DestinationManager {
private:
    vector<shared_ptr<Destination>> destinations;
    mutex destinationMutex;

public:
    DestinationManager() {
        loadDestinations();
    }

    void loadDestinations() {
        ifstream file(DESTINATION_FILE);
        if (!file) return;

        string line;
        while (getline(file, line)) {
            stringstream ss(line);
            string name, description;
            getline(ss, name, ',');
            getline(ss, description, ',');

            auto destination = make_shared<Destination>(name, description);
            destinations.push_back(destination);
        }
        file.close();
    }

    void saveDestinations() {
        ofstream file(DESTINATION_FILE);
        if (!file) {
            Utility::showErrorMessage("Unable to save destination data!");
            return;
        }
        for (const auto &dest : destinations) {
            file << dest->getName() << ","
                 << dest->getDescription() << endl;
        }
        file.close();
    }

    bool addDestination(const string &name, const string &description) {
        lock_guard<mutex> lock(destinationMutex);

        auto it = find_if(destinations.begin(), destinations.end(),
            [&](const shared_ptr<Destination> &dest) {
                return dest->getName() == name;
            });

        if (it != destinations.end()) {
            Utility::showErrorMessage("Destination already exists.");
            return false;
        }

        auto destination = make_shared<Destination>(name, description);
        destinations.push_back(destination);
        Utility::logActivity("Destination added: " + name);
        Utility::showSuccessMessage("Destination added successfully!");
        saveDestinations();
        return true;
    }

    bool updateDestination(const string &name, const string &description) {
        lock_guard<mutex> lock(destinationMutex);

        auto it = find_if(destinations.begin(), destinations.end(),
            [&](const shared_ptr<Destination> &dest) {
                return dest->getName() == name;
            });

        if (it == destinations.end()) {
            Utility::showErrorMessage("Destination not found.");
            return false;
        }

        (*it) = make_shared<Destination>(name, description);
        Utility::logActivity("Destination updated: " + name);
        Utility::showSuccessMessage("Destination updated successfully!");
        saveDestinations();
        return true;
    }
};



