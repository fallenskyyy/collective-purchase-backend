import express from 'express';
import dotenv from 'dotenv';
dotenv.config();
import { supabase } from "./lib/supabase.js";
import { generateAccessToken, generateRefreshToken } from './tokens.js';
import bcrypt from "bcrypt";
import cors from "cors";
import cookieParser from 'cookie-parser'
import jwt from 'jsonwebtoken';


const app = express();

app.use(express.json());

app.use(cors({
  origin: true,
  credentials: true
}));

app.use(cookieParser());

const authenticate = async (req, res, next) => {
  try {
    
    const token = req.cookies.accessToken;
    
    if (!token) {
      return res.status(401).json({ message: "No token provided" });
    }
    
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    
    const { data: { user }, error } = await supabase.auth.admin.getUserById(payload.id);
    
    if (error) {
      return res.status(401).json({ message: "User not found" });
    }
    
    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }
    
    req.user = user;
    next();
  } catch (error) {
    console.error("Authentication error:", error);
    console.error("Error stack:", error.stack);
    return res.status(401).json({ message: "Invalid token", error: error.message });
  }
};

app.post("/auth/register", async (req, res) => {
  const { email, password, name } = req.body;

  try {
    const { data: checkExists, error: checkError } = await supabase
      .rpc('check_email_exists', { email_to_check: email });
    
    if (checkExists) {
      return res.status(409).json({ message: "User already exists" });
    }

    const { data: authData, error: authError } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: {
          name: name,
          created_at: new Date().toISOString(),
        }
      }
    });

    if (authError) {
      console.error('Auth error:', authError);
      return res.status(400).json({ message: authError.message });
    }

    if (!authData.user) {
      return res.status(400).json({ message: "Failed to create user" });
    }

    const accessToken = generateAccessToken(authData.user);
    const refreshToken = generateRefreshToken(authData.user);

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });

    return res.json({
      accessToken,
      user: {
        id: authData.user.id,
        email: authData.user.email,
        name: name,
      },
    });

  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const { data, error } = await supabase.auth.signInWithPassword({
      email: email,
      password: password
    });

    if (error) {
      console.error('Login error:', error);
      
      if (error.message.includes('Invalid login credentials')) {
        return res.status(401).json({ message: "Invalid email or password" });
      }
      
      return res.status(401).json({ message: error.message });
    }

    if (!data.user) {
      return res.status(401).json({ message: "Authentication failed" });
    }

    const userName = data.user.user_metadata?.name || data.user.email?.split('@')[0] || 'User';

    const accessToken = generateAccessToken(data.user);
    const refreshToken = generateRefreshToken(data.user);

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: true,          
      sameSite: "none",       
      maxAge: 15 * 60 * 1000, 
      path: '/',
      domain: undefined 
    });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 30 * 24 * 60 * 60 * 1000,
      path: '/',
      domain: undefined
    });

    return res.json({
      success: true,
      accessToken,
      user: {
        id: data.user.id,
        email: data.user.email,
        name: userName,
        emailConfirmed: data.user.email_confirmed_at ? true : false,
      },
    });

  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/auth/logout", async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    
    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? "strict" : "lax",
    });
    
    res.clearCookie("accessToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? "strict" : "lax",
    });
    
    const { error } = await supabase.auth.signOut();
    
    if (error) {
      console.error('Supabase signOut error:', error);
    }
    
    return res.json({ 
      success: true, 
      message: "Logged out successfully" 
    });
    
  } catch (error) {
    console.error('Logout error:', error);
    return res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/auth/me", async (req, res) => {
  try {
    const token = req.cookies.accessToken
    const payload = jwt.verify(token, process.env.JWT_SECRET);

    const { data: { user }, error } = await supabase.auth.admin.getUserById(payload.id);

    res.json({
      id: user.id,
      email: user.email,
      name: user.name,
    });
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
});

app.post("/api/group-purchases/:offerId/join", authenticate, async (req, res) => {
  try {
    const { offerId } = req.params;
    const userId = req.user?.id;
    const numericOfferId = parseInt(offerId, 10);

    const { data: offer, error: offerError } = await supabase
      .from('group_offers')
      .select('*')
      .eq('id', numericOfferId)
      .single();
    
    if (offerError || !offer) {
      return res.status(404).json({ message: "Group purchase not found" });
    }

    const currentParticipants = offer.current_participants || 0;
    const maxParticipants = offer.required_participants;
    
    if (currentParticipants >= maxParticipants) {
      return res.status(400).json({ message: "Group is full" });
    }

    const { data: existing } = await supabase
      .from('group_participants')
      .select('id')
      .eq('group_offer_id', numericOfferId)
      .eq('user_id', userId)
      .maybeSingle();
    
    if (existing) {
      return res.status(400).json({ message: "You have already joined this group purchase" });
    }

    const newCount = currentParticipants + 1;
    const { error: updateError } = await supabase
      .from('group_offers')
      .update({ current_participants: newCount })
      .eq('id', numericOfferId)
      .eq('current_participants', currentParticipants);
    
    if (updateError) {
      console.error('Update error:', updateError);
      throw updateError;
    }

    const { data: participation, error: joinError } = await supabase
      .from('group_participants')
      .insert({
        group_offer_id: numericOfferId,
        user_id: userId,
        joined_at: new Date().toISOString()
      })
      .select()
      .single();
    
    if (joinError) {
      console.error('Join error:', joinError);
      
      await supabase
        .from('group_offers')
        .update({ current_participants: currentParticipants })
        .eq('id', numericOfferId);
      
      if (joinError.code === '23505') {
        return res.status(400).json({ message: "You have already joined this group purchase" });
      }
      
      throw joinError;
    }
    
    res.json({
      success: true,
      message: "Successfully joined",
      current_participants: newCount
    });
    
  } catch (error) {
    console.error('Join error:', error);
    res.status(500).json({ 
      message: "Internal server error",
      details: error.message 
    });
  }
});

app.get("/api/products/:id", async (req, res) => {
  try {
    const { id } = req.params;
    
    const { data: groupOffer, error } = await supabase
      .from('group_offers')
      .select(`
        *,
        product:products(*)
      `)
      .eq('id', id)
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') {
        return res.status(404).json({ message: "Group purchase not found" });
      }
      throw error;
    }
    
    let userJoined = false;
    const token = req.cookies.accessToken;
    
    if (token && groupOffer) {
      try {
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        const { data: participation } = await supabase
          .from('group_participants')
          .select('id')
          .eq('group_offer_id', id)
          .eq('user_id', payload.id)
          .maybeSingle();
        
        userJoined = !!participation;
      } catch (error) {
        console.log('No valid token');
      }
    }
    
    res.json({
      ...groupOffer,
      user_joined: userJoined
    });
    
  } catch (error) {
    console.error('Error fetching group purchase:', error);
    res.status(500).json({ message: error.message });
  }
});

app.get("/api/group-purchases", async (req, res) => {
  try {
    const token = req.cookies.accessToken;
    let userId = null;
    
    if (token) {
      try {
        const payload = jwt.verify(token, process.env.JWT_SECRET);
      } catch (error) {
        console.log('No valid token, showing public data');
      }
    }

    const { data: groupOffers, error } = await supabase
      .from('group_offers')
      .select(`
        *,
        product:products(*)
      `)
      .order('created_at', { ascending: false });
    
    if (error) throw error;
    if (userId && groupOffers && groupOffers.length > 0) {
      const offerIds = groupOffers.map(o => o.id);
      
      const { data: participations, error: partError } = await supabase
        .from('group_participants')
        .select('group_offer_id')
        .eq('user_id', userId)
        .in('group_offer_id', offerIds);
      
      if (partError) {
        console.error('Error fetching participations:', partError);
      }
      
      
      const enrichedOffers = groupOffers.map(offer => ({
        ...offer,
        user_joined: participations?.some(p => p.group_offer_id === offer.id) || false
      }));
      
      return res.json(enrichedOffers);
    }
    
    res.json(groupOffers);
  } catch (error) {
    console.error('Error fetching group offers:', error);
    res.status(500).json({ message: error.message });
  }
});

app.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
});